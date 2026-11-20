package main

import (
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/reports"
)

// The periodic report operations are in the contract before the reports module implements them: until it does, the
// composite handler answers each with 501 not_implemented (server.Fallback), never a made-up body. An operation the
// module implements is skipped here; its own handler tests cover it.
func TestPeriodicReportOperationsAnswerNotImplementedUntilBuilt(t *testing.T) {
	ops := []string{
		"ReportsGetReportsDefinition", "ReportsPutReportsDefinition", "ReportsGetReportsDocument",
		"ReportsPostReportsSend", "ReportsGetReportsHistory", "ReportsGetReportsHistoryID",
	}
	h := handler{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}}
	own := reflect.TypeOf(&reports.ReportsHandlers{})
	ctx := context.Background()
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			if _, built := own.MethodByName(op); built {
				t.Skipf("%s is implemented by the reports module", op)
			}
			m := reflect.ValueOf(h).MethodByName(op)
			if !m.IsValid() {
				t.Fatalf("%s is not an operation of the generated API", op)
			}
			args := []reflect.Value{reflect.ValueOf(ctx)}
			for i := 1; i < m.Type().NumIn(); i++ {
				args = append(args, reflect.Zero(m.Type().In(i)))
			}
			out := m.Call(args)
			err, _ := out[len(out)-1].Interface().(error)
			if err == nil {
				t.Fatalf("%s answered without an error", op)
			}
			e := h.NewError(ctx, err)
			if e.StatusCode != http.StatusNotImplemented || e.Response.Error.Code != apierr.CodeNotImplemented {
				t.Fatalf("%s: got %d %q, want 501 %q", op, e.StatusCode, e.Response.Error.Code, apierr.CodeNotImplemented)
			}
		})
	}
}
