package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 库文件必须是 0600 —— 只有属主可读写。
//
// 这是 §3.6.3d 的承诺，而它此前只写在文档里、代码里没有任何 chmod。
// SQLite 自己建文件用的是 SQLITE_DEFAULT_FILE_PERMISSIONS（0644）减 umask，
// 默认 umask 022 下就是 **0644：同机其它用户可读**。
//
// 后果不是抽象的：库里躺着明文的样本 —— 完整对话原文与贴进去的代码
// （加密只保护了上游 key）。而 M7 会把 data/ 挂到宿主机上。
//
// 断言按平台门控：Windows 的 ACL 与 Unix mode 位不是一回事，Go 的 Chmod
// 在那里只映射只读位，断言 0600 会恒红。真正需要这条性质的是 Linux 部署。
func TestOpen_DBFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的权限模型是 ACL，mode 位不可比 —— 这条性质在 Linux 部署上验")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "perm.db")

	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// 写一条样本，确保 WAL 里确实有内容 —— 它才是「最新那部分数据」，
	// 只收紧主文件的话，最近写入的样本仍留在 0644 上。
	if err := st.InsertSample(mkSample(1700000000000)); err != nil {
		t.Fatalf("写样本失败: %v", err)
	}
	restrictPerms(path) // 写完再收一次：WAL 是第一次写才出现的

	for _, p := range []string{path, path + "-wal"} {
		fi, err := os.Stat(p)
		if err != nil {
			continue // -wal 可能已被 checkpoint 掉
		}
		if got := fi.Mode().Perm(); got != dbFilePerm {
			t.Errorf("%s 的权限应为 %o，得到 %o —— "+
				"同机其它用户能读到全部对话原文", filepath.Base(p), dbFilePerm, got)
		}
	}
}

// DSN 带 query 时也要能取出文件路径。
//
// 当前调用方传的都是裸路径，但少了这一步的话，哪天有人把带 pragma 的 DSN
// 传进 Open，restrictPerms 会因为 Stat 全部失败而**静默**退化成空操作 ——
// 没有任何输出，谁也不会发现权限其实没收紧。
func TestDBPathOf(t *testing.T) {
	cases := map[string]string{
		"data/x.db": "data/x.db",
		"data/x.db?_pragma=busy_timeout(5000)&_txlock=immediate": "data/x.db",
		":memory:": ":memory:",
		"":         "",
	}
	for in, want := range cases {
		if got := dbPathOf(in); got != want {
			t.Errorf("dbPathOf(%q) = %q，应为 %q", in, got, want)
		}
	}
}
