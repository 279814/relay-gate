package sample

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// 两路采集若在 tee 时读到同一 remaining，Recorder 仍须在每条 insert 前重读占用，
// 合计不得超过 sample_disk_quota_bytes（§5.4）。
func TestRecorder_InsertRechecksDiskQuota(t *testing.T) {
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "quota.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	body := bytes.Repeat([]byte("z"), 2048)
	probe := &model.Sample{RespBody: body, Outcome: model.OutcomeOK}
	if err := st.InsertSample(probe); err != nil {
		t.Fatal(err)
	}
	oneCost, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClearSamples(false); err != nil {
		t.Fatal(err)
	}

	quota := oneCost + oneCost/2
	s := model.DefaultSettings()
	s.SampleQueueSize = 8
	s.SampleDiskQuotaBytes = quota
	s.SampleKeepCount = 0
	s.SampleKeepDays = 0

	r := newTestRecorder(st, s)
	r.Record(&model.Sample{
		ReqID: "a", RespBody: append([]byte(nil), body...), Outcome: model.OutcomeOK,
	})
	r.Record(&model.Sample{
		ReqID: "b", RespBody: append([]byte(nil), body...), Outcome: model.OutcomeOK,
	})
	r.Close()

	used, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if used > quota {
		t.Fatalf("Recorder 串行写入后磁盘 %d 超过配额 %d", used, quota)
	}
	written, dropped := r.Stats()
	if written+dropped != 2 {
		t.Fatalf("两条样本应计入 written+dropped，得到 %d+%d", written, dropped)
	}
	if written < 1 {
		t.Fatal("至少第一条应写入")
	}
}
