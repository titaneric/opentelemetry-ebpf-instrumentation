//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/components/jaeger"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/components/prom"
)

func testREDMetricsForPythonSQLLibrary(t *testing.T, url, comm, namespace string) {
	urlPath := "/query"

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+urlPath, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	var err error
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="` + namespace + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err)
	require.Empty(t, results)

	// Look for a trace with SELECT accounting.contacts
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=SELECT%20accounting.contacts")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: "SELECT"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(100*time.Millisecond))

	// Ensure we don't find any HTTP traces, since we filter them out
	resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2Fquery")
	require.NoError(t, err)
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/query"})
	require.Empty(t, traces)
}

// TODO(matt): uncomment once postgres errors are implemented
// func testREDMetricsForPythonSQLLibraryError(t *testing.T, url, comm string) {
// 	urlPath := "/error"
//
// 	for i := 0; i < 4; i++ {
// 		doHTTPGet(t, url+urlPath, 200)
// 	}
//
// 	// Look for a trace with SELECT nonexisting
// 	test.Eventually(t, testTimeout, func(t require.TestingT) {
// 		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=SELECT%20obi.nonexisting")
// 		require.NoError(t, err)
// 		require.NotNil(t, resp)
// 		require.Equal(t, http.StatusOK, resp.StatusCode)
// 		var tq jaeger.TracesQuery
// 		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
// 		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: "SELECT"})
// 		assert.LessOrEqual(t, 1, len(traces))
// 		assert.LessOrEqual(t, 1, len(traces[0].Spans))
// 		span := traces[0].Spans[0]
// 		assert.Equal(t, "SELECT obi.nonexisting", span.OperationName)
//
// 		tag, found := jaeger.FindIn(span.Tags, "db.response.status_code")
// 		assert.True(t, found)
// 		assert.Equal(t, "TODO:fill", tag.Value)
//
// 		tag, found = jaeger.FindIn(span.Tags, "error.type")
// 		assert.True(t, found)
// 		assert.Equal(t, "TODO:fill", tag.Value)
// 	}, test.Interval(100*time.Millisecond))
// }

func testREDMetricsPythonSQLOnly(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForSQLTestComponents(t, testCaseURL, "/query")
			testREDMetricsForPythonSQLLibrary(t, testCaseURL, "python3.12", "integration-test")
			// testREDMetricsForPythonSQLLibraryError(t, testCaseURL, "python3.12") // TODO(matt): this runs on Postgres, uncomment once it works
		})
	}
}

func testREDMetricsForPythonSQLSSL(t *testing.T, url, comm, namespace string) {
	urlPath := "/query"

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+urlPath, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="` + namespace + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// Look for a trace with SELECT accounting.contacts
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=SELECT%20accounting.contacts")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: "SELECT"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(100*time.Millisecond))

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2Fquery")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/query"})
		require.LessOrEqual(t, 1, len(traces))
		trace := traces[0]
		// Check the information of the parent span
		res := trace.FindByOperationName("GET /query", "")
		require.Len(t, res, 1)
	}, test.Interval(100*time.Millisecond))
}

func testREDMetricsPythonSQLSSL(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsSub(t, testCaseURL, "/query")
			testREDMetricsForPythonSQLSSL(t, testCaseURL, "python3.12", "integration-test")
		})
	}
}
