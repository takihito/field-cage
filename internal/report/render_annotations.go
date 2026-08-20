package report

import (
	"fmt"
	"io"
)

// maxAnnotations caps the annotations emitted for denials. GitHub renders at
// most 10 annotations of each level per step, so emitting more would silently
// drop them; the remainder is reported in a single closing notice instead.
const maxAnnotations = 10

const annotationTitle = "field-cage"

// annotationsRenderer emits GitHub Actions workflow commands. Values are
// escaped with annotationMessage / annotationProperty so a log-derived value
// cannot be interpreted as a new workflow command.
type annotationsRenderer struct{ opts Options }

func (r annotationsRenderer) Render(w io.Writer, s *Summary) error {
	level := resolveLevel(r.opts.AnnotationLevel, s.Mode)
	if level == LevelOff {
		return nil
	}

	denied := s.Denied()
	if len(denied) == 0 {
		_, err := fmt.Fprintf(w, "::notice title=%s::%s\n",
			annotationProperty(annotationTitle),
			annotationMessage(fmt.Sprintf("no denied outbound connections (mode=%s, events=%d)",
				modeLabel(s.Mode), s.Total)))
		return err
	}

	limit := maxAnnotations
	if r.opts.Top > 0 && r.opts.Top < limit {
		limit = r.opts.Top
	}
	for i, d := range denied {
		if i >= limit {
			_, err := fmt.Fprintf(w, "::notice title=%s::%s\n",
				annotationProperty(annotationTitle),
				annotationMessage(fmt.Sprintf("%d more denied destinations not annotated; see the job summary",
					len(denied)-limit)))
			return err
		}
		msg := fmt.Sprintf("denied %s:%d (%s, %d attempt(s), process: %s)",
			d.Destination(), d.Port, d.Verdict, d.Count, processList(d))
		if _, err := fmt.Fprintf(w, "::%s title=%s::%s\n",
			level, annotationProperty(annotationTitle+": denied outbound connection"),
			annotationMessage(msg)); err != nil {
			return err
		}
	}
	return nil
}
