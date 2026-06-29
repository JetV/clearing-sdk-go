// Package canonicalkind 是经济主体 kind 的唯一权威分类法（clearing 定义，单一事实源）。
//
// kind 描述经济资格（谁能持钱包、谁能收款、谁能被交易），是清算层语义，只在此定义一次。
// 各仓最终 import / 引用本包，消除"双写"（auth realm_economics / billing 私扩 / forge provenance）。
package canonicalkind

import "fmt"

// CanonicalKind 是规范化经济主体 kind。
type CanonicalKind string

// 五类一等经济主体。
const (
	KindHuman    CanonicalKind = "human"    // 自然人
	KindAgent    CanonicalKind = "agent"    // 自主 Agent（可持钱包、可被交易）
	KindService  CanonicalKind = "service"  // 系统/客户端服务
	KindProvider CanonicalKind = "provider" // 资源/能力提供者（收入钱包）
	KindOrg      CanonicalKind = "org"      // 组织/团队/项目（共享账户主体）
)

// All 返回全部 canonical kind（稳定顺序，供 GET /v1/kinds）。
func All() []CanonicalKind {
	return []CanonicalKind{KindHuman, KindAgent, KindService, KindProvider, KindOrg}
}

// externalToCanonical 是外部 kind（auth 源令牌形态）→ canonical 的唯一推导表。
var externalToCanonical = map[string]CanonicalKind{
	"user":     KindHuman,
	"client":   KindService,
	"agent":    KindAgent,
	"realm":    KindOrg,
	"provider": KindProvider,
}

// Mapping 返回外部 kind → canonical 的映射（拷贝，供 GET /v1/kinds 与下游引用）。
func Mapping() map[string]CanonicalKind {
	out := make(map[string]CanonicalKind, len(externalToCanonical))
	for k, v := range externalToCanonical {
		out[k] = v
	}
	return out
}

// ErrUnknownKind 表示外部 kind 未知（不静默兜底）。
var ErrUnknownKind = fmt.Errorf("canonicalkind: unknown external kind")

// Derive 把外部 kind 映射为 canonical kind；未知值返回错误而非兜底（不静默原则）。
//
//	user -> human   client -> service   agent -> agent
//	realm -> org     provider -> provider   其他 -> ErrUnknownKind
func Derive(externalKind string) (CanonicalKind, error) {
	if c, ok := externalToCanonical[externalKind]; ok {
		return c, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownKind, externalKind)
}

// Valid 判断给定值是否为合法 canonical kind。
func Valid(k CanonicalKind) bool {
	switch k {
	case KindHuman, KindAgent, KindService, KindProvider, KindOrg:
		return true
	}
	return false
}
