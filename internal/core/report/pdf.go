package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

// pdfPageLines is how many text lines fit on one A4 page at the type size used
// here. Reported evidence is long, so the writer paginates rather than
// truncating.
const pdfPageLines = 62

// WritePDF renders the report as a PDF (FR-R3). It writes the same text the
// text report contains, split across pages, using nothing beyond the standard
// library: a catalog, a page tree, one content stream per page, a Helvetica
// font and a cross-reference table.
func WritePDF(w io.Writer, in Input) error {
	text, err := WriteTextString(in)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	var pages [][]string
	for i := 0; i < len(lines); i += pdfPageLines {
		end := i + pdfPageLines
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[i:end])
	}
	if len(pages) == 0 {
		pages = [][]string{{""}}
	}

	// Object plan: 1 catalog, 2 page tree, then a page and its content stream
	// per page, then the font, then the document information dictionary.
	fontObj := 3 + 2*len(pages)
	infoObj := fontObj + 1

	var buf bytes.Buffer
	offsets := make([]int, infoObj+1)

	obj := func(num int, body string) {
		offsets[num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", num, body)
	}

	buf.WriteString("%PDF-1.4\n")
	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")

	kids := make([]string, 0, len(pages))
	for i := range pages {
		kids = append(kids, fmt.Sprintf("%d 0 R", 3+2*i))
	}
	obj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kids, " "), len(pages)))

	for i, page := range pages {
		pageObj := 3 + 2*i
		contentObj := pageObj + 1
		obj(pageObj, fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>",
			fontObj, contentObj))

		stream := pdfContentStream(page)
		obj(contentObj, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}

	obj(fontObj, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj(infoObj, fmt.Sprintf("<< /Title (%s) /Producer (%s %s) /CreationDate (D:%s) >>",
		pdfEscape(in.Meta.ToolName), pdfEscape(in.Meta.ToolName), pdfEscape(in.Meta.Version),
		pdfDate(in.Meta.When)))

	xrefAt := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", infoObj+1)
	for num := 1; num <= infoObj; num++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[num])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		infoObj+1, infoObj, xrefAt)

	_, err = w.Write(buf.Bytes())
	return err
}

// pdfContentStream builds the text-drawing operators for one page.
func pdfContentStream(lines []string) string {
	var b strings.Builder
	b.WriteString("BT\n/F1 9 Tf\n12 TL\n40 800 Td\n")
	for i, line := range lines {
		if i > 0 {
			b.WriteString("T*\n")
		}
		b.WriteString("(" + pdfEscape(line) + ") Tj\n")
	}
	b.WriteString("ET")
	return b.String()
}

// pdfEscape makes text safe inside a PDF literal string: the delimiters and the
// escape character are escaped, and anything outside printable ASCII (a page
// break, a non-Latin character) becomes a placeholder rather than corrupting
// the content stream.
func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString("    ")
		case r < 32 || r > 126:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pdfDate formats a timestamp the way a PDF information dictionary expects.
func pdfDate(t time.Time) string {
	if t.IsZero() {
		return "00000000000000"
	}
	return t.UTC().Format("20060102150405") + "Z"
}
