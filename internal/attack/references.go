package attack

import (
	"fmt"
	"sort"
	"strings"
)

// ReferenceIssue identifies a nonempty detection reference without a local target.
// It does not imply that the object is absent from every ATT&CK domain.
type ReferenceIssue struct {
	SourceID   string
	TargetType string
	TargetID   string
}

func (issue ReferenceIssue) String() string {
	return fmt.Sprintf("%s -> %s %s: unavailable in this matrix cache", issue.SourceID, strings.ReplaceAll(issue.TargetType, "_", " "), issue.TargetID)
}

// CacheReferenceIssues checks embedded detection-to-analytic and
// analytic-to-component references, including analytics not linked to a strategy.
func CacheReferenceIssues(cache CacheData) []ReferenceIssue {
	checker := newReferenceChecker(cache)
	for _, detection := range cache.DetectionStrategies {
		checker.checkAnalytics(detection)
	}
	for _, analytic := range cache.Analytics {
		checker.checkComponents(analytic)
	}
	return checker.sortedIssues()
}

// AnalyticReferenceIssues reports component references that cannot be resolved.
func AnalyticReferenceIssues(cache CacheData, analyticID string) []ReferenceIssue {
	analytic, found := FindAnalytic(cache, analyticID)
	if !found {
		return nil
	}
	checker := newReferenceChecker(cache)
	checker.checkComponents(analytic)
	return checker.sortedIssues()
}

// DetectionReferenceIssues also checks components on the strategy's linked analytics.
func DetectionReferenceIssues(cache CacheData, detectionID string) []ReferenceIssue {
	detection, found := FindDetectionStrategy(cache, detectionID)
	if !found {
		return nil
	}
	checker := newReferenceChecker(cache)
	checker.checkAnalytics(detection)
	for _, ref := range detection.Analytics {
		if analytic, found := checker.analytics[ref]; found {
			checker.checkComponents(analytic)
		}
	}
	return checker.sortedIssues()
}

type referenceChecker struct {
	analytics  map[string]Analytic
	components map[string]DataComponent
	issues     map[ReferenceIssue]struct{}
}

func newReferenceChecker(cache CacheData) referenceChecker {
	return referenceChecker{
		analytics:  indexAnalytics(cache.Analytics),
		components: indexComponents(cache.DataComponents),
		issues:     make(map[ReferenceIssue]struct{}),
	}
}

func (checker referenceChecker) checkAnalytics(detection DetectionStrategy) {
	sourceID := detection.ID
	if sourceID == "" {
		sourceID = detection.StixID
	}
	for _, ref := range detection.Analytics {
		if _, found := checker.analytics[ref]; !found && strings.TrimSpace(ref) != "" {
			checker.issues[ReferenceIssue{sourceID, "analytic", ref}] = struct{}{}
		}
	}
}

func (checker referenceChecker) checkComponents(analytic Analytic) {
	sourceID := analytic.ID
	if sourceID == "" {
		sourceID = analytic.StixID
	}
	for _, ref := range analytic.DataComponents {
		if _, found := checker.components[ref]; !found && strings.TrimSpace(ref) != "" {
			checker.issues[ReferenceIssue{sourceID, "data_component", ref}] = struct{}{}
		}
	}
}

func (checker referenceChecker) sortedIssues() []ReferenceIssue {
	var issues []ReferenceIssue
	for issue := range checker.issues {
		issues = append(issues, issue)
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].SourceID != issues[j].SourceID {
			return issues[i].SourceID < issues[j].SourceID
		}
		if issues[i].TargetType != issues[j].TargetType {
			return issues[i].TargetType < issues[j].TargetType
		}
		return issues[i].TargetID < issues[j].TargetID
	})
	return issues
}
