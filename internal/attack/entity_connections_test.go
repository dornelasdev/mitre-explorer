package attack

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEntityConnectionQueries(t *testing.T) {
	for _, tc := range []struct {
		name, kind, sourceType, targetType, anchorID string
		incoming                                     bool
		want                                         []string
		query                                        func(CacheData, string) []string
	}{
		{"group software", "uses", "group", "software", "G0001", false, []string{"S0001", "S0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(SoftwareUsedByGroup(cache, id), func(item Software) string { return item.ID })
		}},
		{"software groups", "uses", "group", "software", "S0001", true, []string{"G0001", "G0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(GroupsUsingSoftware(cache, id), func(item Group) string { return item.ID })
		}},
		{"campaign software", "uses", "campaign", "software", "C0001", false, []string{"S0001", "S0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(SoftwareUsedByCampaign(cache, id), func(item Software) string { return item.ID })
		}},
		{"software campaigns", "uses", "campaign", "software", "S0001", true, []string{"C0001", "C0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(CampaignsUsingSoftware(cache, id), func(item Campaign) string { return item.ID })
		}},
		{"group campaigns", "attributed-to", "campaign", "group", "G0001", true, []string{"C0001", "C0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(CampaignsAttributedToGroup(cache, id), func(item Campaign) string { return item.ID })
		}},
		{"campaign groups", "attributed-to", "campaign", "group", "C0001", false, []string{"G0001", "G0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(GroupsForCampaign(cache, id), func(item Group) string { return item.ID })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := CacheData{
				Groups:    []Group{{ID: "G0002"}, {ID: "G0001"}, {ID: "G0001"}},
				Softwares: []Software{{ID: "S0002"}, {ID: "S0001"}, {ID: "S0001"}},
				Campaigns: []Campaign{{ID: "C0002"}, {ID: "C0001"}, {ID: "C0001"}},
			}
			edge := func(relatedID string) Relationship {
				sourceID, targetID := tc.anchorID, relatedID
				if tc.incoming {
					sourceID, targetID = relatedID, tc.anchorID
				}
				return Relationship{Type: tc.kind, SourceType: tc.sourceType, SourceID: sourceID, TargetType: tc.targetType, TargetID: targetID}
			}
			cache.Relationships = []Relationship{edge(tc.want[1]), edge(tc.want[0]), edge(tc.want[0]), edge("MISSING"), edge("")}
			for _, input := range []string{tc.anchorID, strings.ToLower(tc.anchorID), " " + tc.anchorID + " "} {
				if got := tc.query(cache, input); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%q = %v; want %v", input, got, tc.want)
				}
			}
			for _, input := range []string{"", " ", "unknown"} {
				if got := tc.query(cache, input); len(got) != 0 {
					t.Fatalf("invalid anchor %q returned %v", input, got)
				}
			}
			for _, kind := range []string{"wrong relationship", "wrong source type", "wrong target type", "wrong anchor", "reversed edge"} {
				t.Run(kind, func(t *testing.T) {
					rel := edge(tc.want[0])
					switch kind {
					case "wrong relationship":
						rel.Type = "wrong"
					case "wrong source type":
						rel.SourceType = "wrong"
					case "wrong target type":
						rel.TargetType = "wrong"
					case "wrong anchor":
						if tc.incoming {
							rel.TargetID = "OTHER"
						} else {
							rel.SourceID = "OTHER"
						}
					case "reversed edge":
						rel.SourceID, rel.TargetID = rel.TargetID, rel.SourceID
						rel.SourceType, rel.TargetType = rel.TargetType, rel.SourceType
					}
					cache.Relationships = []Relationship{rel}
					if got := tc.query(cache, tc.anchorID); len(got) != 0 {
						t.Fatalf("unrelated edge produced %v", got)
					}
				})
			}
			cache.Relationships = nil
			if got := tc.query(cache, tc.anchorID); len(got) != 0 {
				t.Fatalf("empty connection returned %v", got)
			}
			cache.Relationships = []Relationship{edge(tc.want[0])}
			anchorType := tc.sourceType
			if tc.incoming {
				anchorType = tc.targetType
			}
			switch anchorType {
			case "group":
				cache.Groups = nil
			case "software":
				cache.Softwares = nil
			case "campaign":
				cache.Campaigns = nil
			}
			if got := tc.query(cache, tc.anchorID); len(got) != 0 {
				t.Fatalf("missing anchor object returned %v", got)
			}
		})
	}
}

func TestEntityConnectionsDoNotInferTransitiveLinks(t *testing.T) {
	cache := CacheData{
		Groups:    []Group{{ID: "G0001"}, {ID: "G0002"}},
		Softwares: []Software{{ID: "S0001"}, {ID: "S0002"}},
		Campaigns: []Campaign{{ID: "C0001"}, {ID: "C0002"}},
		Relationships: []Relationship{
			{Type: "uses", SourceType: "group", SourceID: "G0001", TargetType: "software", TargetID: "S0001"},
			{Type: "uses", SourceType: "group", SourceID: "G0002", TargetType: "software", TargetID: "S0002"},
			{Type: "uses", SourceType: "campaign", SourceID: "C0001", TargetType: "software", TargetID: "S0002"},
			{Type: "uses", SourceType: "campaign", SourceID: "C0002", TargetType: "software", TargetID: "S0002"},
			{Type: "attributed-to", SourceType: "campaign", SourceID: "C0001", TargetType: "group", TargetID: "G0001"},
		},
	}
	if got := SoftwareUsedByGroup(cache, "G0001"); len(got) != 1 || got[0].ID != "S0001" {
		t.Fatalf("group inherited campaign software: %+v", got)
	}
	if got := SoftwareUsedByCampaign(cache, "C0001"); len(got) != 1 || got[0].ID != "S0002" {
		t.Fatalf("campaign inherited group software: %+v", got)
	}
	if got := GroupsUsingSoftware(cache, "S0002"); len(got) != 1 || got[0].ID != "G0002" {
		t.Fatalf("software inherited a campaign's group: %+v", got)
	}
	if got := CampaignsUsingSoftware(cache, "S0001"); len(got) != 0 {
		t.Fatalf("software inherited a group's campaign: %+v", got)
	}
	if got := GroupsForCampaign(cache, "C0002"); len(got) != 0 {
		t.Fatalf("shared software inferred attribution: %+v", got)
	}
	if got := CampaignsAttributedToGroup(cache, "G0001"); len(got) != 1 || got[0].ID != "C0001" {
		t.Fatalf("shared software inferred campaign: %+v", got)
	}
}

func TestEntityConnectionsPreserveValuesAndCacheOrder(t *testing.T) {
	cache := CacheData{
		Groups:    []Group{{ID: "G0001", Name: "Group", Description: "Details", Aliases: []string{"Alias"}}},
		Softwares: []Software{{ID: "S0002", Name: "Tool", Type: "tool"}, {ID: "S0001", Name: "Malware", Type: "malware", Description: "Details", Aliases: []string{"Alias"}}},
		Campaigns: []Campaign{{ID: "C0001", Name: "Campaign", Description: "Details", Aliases: []string{"Alias"}}},
		Relationships: []Relationship{
			{Type: "uses", SourceType: "group", SourceID: "g0001", TargetType: "software", TargetID: "s0001"},
			{Type: "uses", SourceType: "group", SourceID: "G0001", TargetType: "software", TargetID: "S0002"},
			{Type: "uses", SourceType: "campaign", SourceID: "C0001", TargetType: "software", TargetID: "S0001"},
		},
	}
	if got := SoftwareUsedByGroup(cache, "G0001"); !reflect.DeepEqual(got, []Software{cache.Softwares[1], cache.Softwares[0]}) {
		t.Fatalf("software values or sorting changed: %+v", got)
	}
	if got := GroupsUsingSoftware(cache, "S0001"); !reflect.DeepEqual(got, cache.Groups) {
		t.Fatalf("group fields lost: %+v", got)
	}
	if got := CampaignsUsingSoftware(cache, "S0001"); !reflect.DeepEqual(got, cache.Campaigns) {
		t.Fatalf("campaign fields lost: %+v", got)
	}
	if cache.Softwares[0].ID != "S0002" {
		t.Fatal("query reordered cache")
	}
}

func TestEntityConnectionsFromNormalizedSTIX(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/entity-connections.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := SaveCacheData(path, cache); err != nil {
		t.Fatal(err)
	}
	cache, err = LoadCacheData(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := SoftwareUsedByGroup(cache, "G0001"); len(got) != 1 || got[0].ID != "S0001" {
		t.Fatalf("group software: %+v", got)
	}
	if got := GroupsUsingSoftware(cache, "S0001"); len(got) != 1 || got[0].ID != "G0001" {
		t.Fatalf("software groups: %+v", got)
	}
	if got := SoftwareUsedByCampaign(cache, "C0001"); len(got) != 1 || got[0].ID != "S0001" {
		t.Fatalf("campaign software: %+v", got)
	}
	if got := CampaignsUsingSoftware(cache, "S0001"); len(got) != 1 || got[0].ID != "C0001" {
		t.Fatalf("software campaigns: %+v", got)
	}
	if got := CampaignsAttributedToGroup(cache, "G0001"); len(got) != 1 || got[0].ID != "C0001" {
		t.Fatalf("attributed campaigns: %+v", got)
	}
	if got := GroupsForCampaign(cache, "C0001"); len(got) != 1 || got[0].ID != "G0001" {
		t.Fatalf("attributed groups: %+v", got)
	}
}
