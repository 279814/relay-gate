package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 脏行/历史短 api_key：留空或 MaskKey 回显不得在部分更新时成功留下短钥；
// 换 >= MinRedactableKeyLen 的新钥应替换；被拒时整行不变。
func TestUpdateUpstreamRejectsKeepWhenStoredKeyShorterThanMinRedactable(t *testing.T) {
	st := testStore(t)
	short := strings.Repeat("x", model.MinRedactableKeyLen-1)
	u := &model.Upstream{Name: "dirty-short", BaseURL: "https://a.com", APIKey: "sk-long-enough12", Enabled: true}
	if err := st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	enc, err := st.cipher.Encrypt(short)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE upstream SET api_key_enc=? WHERE id=?`, enc, u.ID); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.APIKey != short {
		t.Fatalf("plant short key failed: got %q", got.APIKey)
	}

	got.Name = "dirty-renamed"
	got.APIKey = ""
	err = st.UpdateUpstream(got)
	if err == nil {
		t.Fatal("留空保留短 key 的部分更新应被拒绝")
	}
	if !errors.Is(err, model.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	afterEmpty, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterEmpty.APIKey != short || afterEmpty.Name != "dirty-short" {
		t.Fatalf("拒绝后整行应不变：key=%q name=%q", afterEmpty.APIKey, afterEmpty.Name)
	}

	got.Name = "dirty-mask"
	got.APIKey = MaskKey(short)
	err = st.UpdateUpstream(got)
	if err == nil {
		t.Fatal("MaskKey 回显保留短 key 的部分更新应被拒绝")
	}
	if !errors.Is(err, model.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	afterMask, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterMask.APIKey != short || afterMask.Name != "dirty-short" {
		t.Fatalf("拒绝后整行应不变：key=%q name=%q", afterMask.APIKey, afterMask.Name)
	}

	exact := strings.Repeat("z", model.MinRedactableKeyLen)
	got.APIKey = exact
	got.Name = "dirty-fixed"
	if err := st.UpdateUpstream(got); err != nil {
		t.Fatalf("换足够长的新 key 应成功：%v", err)
	}
	final, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.APIKey != exact || final.Name != "dirty-fixed" {
		t.Fatalf("got key=%q name=%q want key=%q name=dirty-fixed", final.APIKey, final.Name, exact)
	}
}
