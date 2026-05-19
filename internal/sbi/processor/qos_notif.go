package processor

// qos_notif.go — QoS Notification Control (QNC) and Alternative QoS
// Profiles (AQoSP) for the PCF SM-Policy processor.
//
// Drop alongside smpolicy.go in NFs/pcf/internal/sbi/processor/.
//
// Spec references:
//   TS 29.512 §5.6.2.7 — QosData (Qnc bool, GbrUl, GbrDl,
//                         PacketDelayBudget, PacketErrorRate)
//   TS 29.512 §5.6.2.6 — PccRule.RefAltQosParams []string
//   TS 29.512 §5.6.2.5 — SmPolicyDecision.QosDecs contains BOTH the primary
//                         QosData AND the alternative QosData entries;
//                         RefAltQosParams on PccRule points to the alt IDs.
//   TS 38.413 §9.3.1.152 — NGAP AlternativeQoSParaSetList (max 8, 1-based)
//
// NO changes to openapi models are needed — alternative QoS profiles are
// plain QosData entries stored in SmPolicyDecision.QosDecs, exactly as
// specified in TS 29.512 Table 5.6.2.5-1. //kassem — entire file is new

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
)

// maxAltQosSets is the NGAP maximum for AlternativeQoSParaSetList. //kassem
const maxAltQosSets = 8 //kassem

// gbrStandardised5QIs lists the standardised GBR resource-type 5QIs
// from TS 23.501 Table 5.7.4-1. //kassem
var gbrStandardised5QIs = map[int32]bool{ //kassem
	1: true, 2: true, 3: true, 4: true,
	65: true, 66: true, 67: true,
	71: true, 72: true, 73: true, 74: true, 75: true, 76: true,
}

// isGbrQosData reports whether qd represents a GBR QoS flow. //kassem
func isGbrQosData(qd *models.QosData) bool { //kassem
	if qd == nil {
		return false
	}
	if qd.GbrUl != "" || qd.GbrDl != "" {
		return true
	}
	return gbrStandardised5QIs[qd.Var5qi]
}

// altQosId builds the QosData ID for an alternative QoS entry.
// These IDs go into SmPolicyDecision.QosDecs AND into
// PccRule.RefAltQosParams. Convention: "<primaryQosId>-alt<N>"
// where N is 1-based (matching NGAP AlternativeQoSParaSetIndex). //kassem
func altQosId(primaryQosId string, ngapIndex int32) string { //kassem
	return fmt.Sprintf("%s-alt%d", primaryQosId, ngapIndex)
}

// generateAltQosEntries derives up to maxAltQosSets QosData entries from
// the primary QosData and inserts them directly into decision.QosDecs. //kassem
//
// Generation rule (kassem):
//   For NGAP index N (N = 1 .. 8):
//     GbrDl[N]             = primaryGbrDl          / (N+1)   — less DL GBR
//     GbrUl[N]             = primaryGbrUl           / (N+1)   — less UL GBR
//     PacketDelayBudget[N] = primaryPacketDelayBudget * (N+1) — more delay tolerated
//     PacketErrorRate      = unchanged               — same error tolerance
//     Var5qi               = same as primary
//     Qnc                  = false (notification control only on primary)
//
// Each alt entry is a full QosData stored in SmPolicyDecision.QosDecs under
// its altQosId key. PccRule.RefAltQosParams is then set to the list of those keys.
//
// Returns the ordered list of alt QosData IDs (empty if none generated).
func generateAltQosEntries( //kassem
	primary *models.QosData,
	primaryQosId string,
	decision *models.SmPolicyDecision,
) []string { //kassem
	if primary == nil || decision == nil {
		return nil
	}

	primaryGbrUl, hasGbrUl := parseBitRate(primary.GbrUl) //kassem
	primaryGbrDl, hasGbrDl := parseBitRate(primary.GbrDl) //kassem

	if !hasGbrUl && !hasGbrDl {
		return nil // no GBR parameters to derive from
	}

	if decision.QosDecs == nil {
		decision.QosDecs = make(map[string]*models.QosData)
	}

	altIds := make([]string, 0, maxAltQosSets) //kassem

	for n := int32(1); n <= maxAltQosSets; n++ { //kassem
		divisor := float64(n + 1) // alt-1 ÷ 2, alt-2 ÷ 3, ..., alt-7 ÷ 8 //kassem

		altEntry := &models.QosData{ //kassem
			QosId:  altQosId(primaryQosId, n), //kassem
			Var5qi: primary.Var5qi,             // same 5QI as primary //kassem
			Qnc:    false,                       // QNC only on primary //kassem
		}

		if hasGbrDl { //kassem
			val := primaryGbrDl / divisor //kassem
			if val < 1 {
				break // remaining sets would be ~0 kbps, stop //kassem
			}
			altEntry.GbrDl = formatBitRate(val) //kassem
		}
		if hasGbrUl { //kassem
			val := primaryGbrUl / divisor //kassem
			if val < 1 {
				break //kassem
			}
			altEntry.GbrUl = formatBitRate(val) //kassem
		}

		// Relax PacketDelayBudget proportionally. //kassem
		if primary.PacketDelayBudget > 0 { //kassem
			altEntry.PacketDelayBudget = primary.PacketDelayBudget * (n + 1) //kassem
		}

		// Carry the same PacketErrorRate tolerance. //kassem
		if primary.PacketErrorRate != "" { //kassem
			altEntry.PacketErrorRate = primary.PacketErrorRate //kassem
		}

		// Store the alt QosData entry in SmPolicyDecision.QosDecs. //kassem
		decision.QosDecs[altEntry.QosId] = altEntry //kassem
		altIds = append(altIds, altEntry.QosId)      //kassem

		logger.SmPolicyLog.Debugf( //kassem
			"[AQoSP] QosDecs[%s]: GbrDl=%s GbrUl=%s PDB=%dms PER=%s", //kassem
			altEntry.QosId, altEntry.GbrDl, altEntry.GbrUl, //kassem
			altEntry.PacketDelayBudget, altEntry.PacketErrorRate) //kassem
	}

	return altIds
}

// applyQncAndAltQoS enriches SmPolicyDecision for every GBR QosData: //kassem
//
//  1. Sets QosData.Qnc = true on the primary entry
//     (QNC — TS 29.512 §5.6.2.7; Qnc bool is the correct field in v1.2.4).
//
//  2. Generates alternative QosData entries in SmPolicyDecision.QosDecs
//     (TS 29.512 §5.6.2.5 — alts live in the same QosDecs map as the primary).
//
//  3. Sets PccRule.RefAltQosParams to the ordered list of alt QosData IDs
//     on every PccRule that references this primary QosData
//     (TS 29.512 §5.6.2.6; RefAltQosParams []string exists in v1.2.4).
//
// Must be called AFTER QosDecs and PccRules are fully built, BEFORE c.JSON(). //kassem
func applyQncAndAltQoS( //kassem
	smPolicyData *pcf_context.UeSmPolicyData,
	decision *models.SmPolicyDecision,
) {
	if decision == nil || len(decision.QosDecs) == 0 {
		return
	}

	// Collect primary GBR QosData IDs first to avoid mutating the map
	// while iterating it (alt entries are added to the same map). //kassem
	type primaryEntry struct {
		id string
		qd *models.QosData
	}
	var primaries []primaryEntry //kassem
	for qosId, qd := range decision.QosDecs {
		if isGbrQosData(qd) {
			primaries = append(primaries, primaryEntry{qosId, qd})
		}
	}

	for _, p := range primaries { //kassem
		qosId := p.id
		qd := p.qd

		// ── 1. QoS Notification Control ──────────────────────────── //kassem
		// Qnc is the correct field name in free5gc/openapi v1.2.4.    //kassem
		// (NotifControl does not exist in this version.)               //kassem
		qd.Qnc = true //kassem
		decision.QosDecs[qosId] = qd
		logger.SmPolicyLog.Debugf(
			"[QNC] QosData[%s] 5QI[%d]: Qnc=true", qosId, qd.Var5qi)

		// ── 2. Generate alt QosData entries into QosDecs ─────────── //kassem
		altIds := generateAltQosEntries(qd, qosId, decision) //kassem
		if len(altIds) == 0 {
			continue
		}
		logger.SmPolicyLog.Infof(
			"[AQoSP] QosData[%s]: generated %d alt entries: %v", qosId, len(altIds), altIds)

		// Track in session context for reuse during update. //kassem
		smPolicyData.AltQosParaSets[qosId] = altIds //kassem

		// ── 3. Wire RefAltQosParams on PccRules referencing this QosData ── //kassem
		for pccRuleId, pccRule := range decision.PccRules { //kassem
			for _, refQos := range pccRule.RefQosData { //kassem
				if refQos == qosId { //kassem
					pccRule.RefAltQosParams = altIds        //kassem
					decision.PccRules[pccRuleId] = pccRule //kassem
					logger.SmPolicyLog.Debugf(              //kassem
						"[AQoSP] PccRule[%s] RefAltQosParams=%v", pccRuleId, altIds) //kassem
					break
				}
			}
		}
	}
}

// parseBitRate parses a free5GC bit-rate string (e.g. "100 Mbps") into Kbps. //kassem
func parseBitRate(s string) (float64, bool) { //kassem
	if s == "" {
		return 0, false
	}
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0, false
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil || val <= 0 {
		return 0, false
	}
	switch parts[1] {
	case "Tbps":
		val *= 1024 * 1024 * 1024
	case "Gbps":
		val *= 1024 * 1024
	case "Mbps":
		val *= 1024
	case "Kbps":
		// already Kbps
	case "bps":
		val /= 1024
	default:
		return 0, false
	}
	return val, true
}

// formatBitRate converts Kbps float64 to a human-readable bit-rate string. //kassem
func formatBitRate(kbps float64) string { //kassem
	switch {
	case kbps >= 1024*1024*1024:
		return fmt.Sprintf("%.0f Tbps", kbps/(1024*1024*1024))
	case kbps >= 1024*1024:
		return fmt.Sprintf("%.0f Gbps", kbps/(1024*1024))
	case kbps >= 1024:
		return fmt.Sprintf("%.0f Mbps", kbps/1024)
	case kbps >= 1:
		return fmt.Sprintf("%.0f Kbps", kbps)
	default:
		return fmt.Sprintf("%.0f bps", kbps*1024)
	}
}