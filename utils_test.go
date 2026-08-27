package main

import (
	"strings"
	"testing"
)

// --- 门户配置提取：起始标记兼容换行/空格/属性等多种页面形态 ---

func TestFormatEConfigTagVariants(t *testing.T) {
	configBody := "<config><ticket-url>t</ticket-url><auth-url>a</auth-url></config>"

	cases := []struct {
		name string
		page string
	}{
		{
			name: "newline after start tag",
			page: "<!DOCTYPE html><!--//config.campus.js.chinatelecom.com\n" + configBody + "\n//config.campus.js.chinatelecom.com-->",
		},
		{
			name: "space+attrs after start tag",
			page: "<!--//config.campus.js.chinatelecom.com width=720 height=480\n" + configBody + "//config.campus.js.chinatelecom.com-->",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := FormatEConfig([]byte(tc.page))
			if err != nil {
				t.Fatalf("extract failed: %v", err)
			}
			if !strings.HasPrefix(string(out), "<config>") {
				t.Fatalf("expected trimmed config XML, got %q", string(out))
			}
			if !strings.Contains(string(out), "ticket-url") {
				t.Fatal("config content lost")
			}
		})
	}

	if _, err := FormatEConfig([]byte("<html>nothing here</html>")); err == nil {
		t.Fatal("missing start tag should error")
	}
}

// --- ZSM 响应解析：官方格式为分隔符 '$' 后接定长 36 字节 UUID ---

func TestDecodeAlgoIDOfficialZSMFormat(t *testing.T) {
	key := []byte("testkey")
	id := []byte(AlgoXTea) // 36 字符

	payload := []byte{0x00, 0x00, 0x00, byte(len(key))}
	payload = append(payload, key...)
	payload = append(payload, '$')
	payload = append(payload, id...)
	payload = append(payload, '\'')        // 尾部分隔符
	payload = append(payload, 0xDE, 0xAD) // 其余二进制数据应被忽略

	gotID, gotKey, err := DecodeAlgoID(payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if gotID != AlgoXTea {
		t.Fatalf("algo id mismatch: %q", gotID)
	}
	if string(gotKey) != "testkey" {
		t.Fatalf("key mismatch: %q", gotKey)
	}

	// 边界：数据过短
	if _, _, err := DecodeAlgoID([]byte{1, 2, 3}); err == nil {
		t.Fatal("short payload should error")
	}
	// 边界：UUID 被截断（去掉分隔符之后的 5 个字节，剩余 ID 字节不足 36）
	if _, _, err := DecodeAlgoID(payload[:len(payload)-5]); err == nil {
		t.Fatal("truncated algo id should error")
	}
}
