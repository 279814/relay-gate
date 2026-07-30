package model

import (
	"errors"
	"strings"
	"testing"
)

// 首 Token 超时的 5 分钟硬下限是刻意设计的约束（§4.2），
// 不是随手取的数字，所以要有测试守住它，防止日后被「顺手改小一点」。
func TestRealFirstTokenFloor(t *testing.T) {
	cases := []struct {
		name    string
		sec     int
		wantErr bool
	}{
		{"低于下限直接拒绝", 299, true},
		{"常见的错误直觉：60 秒", 60, true},
		{"零值也要拒绝", 0, true},
		{"负数", -1, true},
		{"正好等于下限", 300, false},
		{"默认值 20 分钟", 1200, false},
		{"更长也允许", 3600, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := DefaultSettings()
			s.RealFirstTokenSec = c.sec
			// 总时长必须容得下首 Token，否则会先撞另一条校验，测不到本条
			if c.sec > s.RealTotalSec {
				s.RealTotalSec = c.sec
			}

			err := s.Validate()
			if c.wantErr {
				if err == nil {
					t.Fatalf("%d 秒应被拒绝，却通过了", c.sec)
				}
				if !errors.Is(err, ErrValidation) {
					t.Errorf("错误应可被 errors.Is(ErrValidation) 识别，否则 API 层会回 500 而非 400；得到 %v", err)
				}
				// 错误信息要指出正确的替代做法，否则用户只会反复改这一个值
				if !strings.Contains(err.Error(), "l2_first_token_sec") {
					t.Errorf("错误信息应提示改探活超时，得到：%v", err)
				}
			} else if err != nil {
				t.Fatalf("%d 秒应被接受，却报错：%v", c.sec, err)
			}
		})
	}
}

func TestDefaultSettingsAreValid(t *testing.T) {
	s := DefaultSettings()
	if err := s.Validate(); err != nil {
		t.Fatalf("默认配置必须自洽，否则首次启动就是坏的：%v", err)
	}
}

// 总时长小于首 Token 超时时，总超时会先触发，导致首 Token 超时形同虚设。
func TestTotalMustCoverFirstToken(t *testing.T) {
	s := DefaultSettings()
	s.RealFirstTokenSec = 1200
	s.RealTotalSec = 600
	if err := s.Validate(); err == nil {
		t.Fatal("total < first_token 应被拒绝")
	}

	s = DefaultSettings()
	s.L2FirstTokenSec = 200
	s.L2TotalSec = 100
	if err := s.Validate(); err == nil {
		t.Fatal("l2_total < l2_first_token 应被拒绝")
	}
}

func TestSettingsRejectNonPositive(t *testing.T) {
	// 抽查几个：0 值会让探活变成忙循环或除零，必须挡住
	for _, f := range []struct {
		name string
		set  func(*Settings)
	}{
		{"l1_interval_dead_sec", func(s *Settings) { s.L1IntervalDeadSec = 0 }},
		{"fail_threshold", func(s *Settings) { s.FailThreshold = 0 }},
		{"global_l2_concurrency", func(s *Settings) { s.GlobalL2Concurrency = 0 }},
		{"sample_queue_size", func(s *Settings) { s.SampleQueueSize = 0 }},
		{"l2_first_token_sec 负数", func(s *Settings) { s.L2FirstTokenSec = -5 }},
	} {
		t.Run(f.name, func(t *testing.T) {
			s := DefaultSettings()
			f.set(&s)
			if err := s.Validate(); err == nil {
				t.Fatalf("%s 非正数应被拒绝", f.name)
			}
		})
	}
}
