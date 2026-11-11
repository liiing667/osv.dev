package conversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGroupAffectedRanges(t *testing.T) {
	tests := []struct {
		name     string
		affected []*osvschema.Affected
		want     []*osvschema.Affected
	}{
		{
			name: "Merge same introduced",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different introduced - no merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "1.1"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "1.1"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different type - no merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different repo - no merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "repo1",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Repo: "repo2",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "repo1",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Repo: "repo2",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
		},
		{
			name: "Mixed merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "2.0"},
								{Fixed: "3.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "2.0"},
								{Fixed: "3.0"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different DatabaseSpecific (non-versions) - merge properly",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewStringValue("bar"),
								},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewStringValue("baz"),
								},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("bar"),
											structpb.NewStringValue("baz"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Merge DatabaseSpecific extracted events",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"extracted_events": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
										},
									}),
								},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"extracted_events": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"extracted_events": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Deduplicate DatabaseSpecific extracted events",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"extracted_events": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
										},
									}),
								},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"extracted_events": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"extracted_events": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GroupAffectedRanges(tt.affected)
			if diff := cmp.Diff(tt.want, tt.affected, protocmp.Transform()); diff != "" {
				t.Errorf("groupAffectedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGroupRanges(t *testing.T) {
	mustMakeDBSpecific := func(m map[string]any) *structpb.Struct {
		ds, err := utility.NewStructpbFromMap(m)
		if err != nil {
			t.Fatalf("failed to make database specific: %v", err)
		}

		return ds
	}

	extractedEvents := func(events []*osvschema.Event, source string) *structpb.Struct {
		return mustMakeDBSpecific(map[string]any{
			"extracted_events": []any{
				map[string]any{
					"range":  events,
					"source": source,
				},
			},
		})
	}

	tests := []struct {
		name   string
		ranges []models.RangeWithMetadata
		want   []models.RangeWithMetadata
	}{
		{
			// The two input ranges share the same repo and introduced value but use
			// mutually exclusive terminal boundaries. They must stay independent, and
			// each output range keeps its original source for auditability.
			name: "fixed and last_affected conflict kept independent with provenance",
			ranges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "https://github.com/foo/bar",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
						DatabaseSpecific: extractedEvents(
							[]*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0"}}, "CPE_RANGE"),
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "https://github.com/foo/bar",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "0.9"},
						},
						DatabaseSpecific: extractedEvents(
							[]*osvschema.Event{{Introduced: "0"}, {LastAffected: "0.9"}}, "CPE_STRING"),
					},
				},
			},
			want: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "https://github.com/foo/bar",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
						DatabaseSpecific: extractedEvents(
							[]*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0"}}, "CPE_RANGE"),
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "https://github.com/foo/bar",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "0.9"},
						},
						DatabaseSpecific: extractedEvents(
							[]*osvschema.Event{{Introduced: "0"}, {LastAffected: "0.9"}}, "CPE_STRING"),
					},
				},
			},
		},
		{
			// Conflict resolution must not depend on input ordering. Events arrive
			// interleaved and out of order here.
			name: "conflicting events out of order stay independent and deterministic",
			ranges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{LastAffected: "2.0"},
							{Introduced: "0"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Fixed: "1.5"},
							{Introduced: "0"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
					},
				},
			},
			want: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "2.0"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.5"},
							{Fixed: "1.0"},
						},
					},
				},
			},
		},
		{
			// Multiple fixed boundaries for the same introduced value still merge,
			// including an open-ended range, preserving the historical behaviour.
			name: "multiple fixed and open ended range merge",
			ranges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.2"},
						},
					},
				},
			},
			want: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
							{Fixed: "1.2"},
						},
					},
				},
			},
		},
		{
			// Same introduced value with only last_affected boundaries merges normally.
			name: "multiple last_affected merge",
			ranges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "1.0"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "1.1"},
						},
					},
				},
			},
			want: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "repo",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "1.0"},
							{LastAffected: "1.1"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GroupRanges(tt.ranges)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("GroupRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPartitionMergeableRanges(t *testing.T) {
	rwm := func(repo, introduced string, events ...*osvschema.Event) models.RangeWithMetadata {
		return models.RangeWithMetadata{
			Range: &osvschema.Range{
				Type:   osvschema.Range_GIT,
				Repo:   repo,
				Events: append([]*osvschema.Event{{Introduced: introduced}}, events...),
			},
		}
	}

	t.Run("same introduced fixed and last_affected split, others join default bucket", func(t *testing.T) {
		ranges := []models.RangeWithMetadata{
			rwm("repo", "0", &osvschema.Event{LastAffected: "0.9"}),
			rwm("repo", "2.0", &osvschema.Event{Fixed: "3.0"}),
			rwm("repo", "0", &osvschema.Event{Fixed: "1.0"}),
		}

		buckets := partitionMergeableRanges(ranges)
		if len(buckets) != 2 {
			t.Fatalf("expected 2 buckets, got %d: %+v", len(buckets), buckets)
		}

		wantBucket0 := []models.RangeWithMetadata{ranges[0], ranges[1]}
		wantBucket1 := []models.RangeWithMetadata{ranges[2]}
		if diff := cmp.Diff(wantBucket0, buckets[0], protocmp.Transform()); diff != "" {
			t.Errorf("bucket 0 mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(wantBucket1, buckets[1], protocmp.Transform()); diff != "" {
			t.Errorf("bucket 1 mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("non conflicting ranges stay in a single bucket", func(t *testing.T) {
		ranges := []models.RangeWithMetadata{
			rwm("repo", "0", &osvschema.Event{Fixed: "1.0"}),
			rwm("repo", "0", &osvschema.Event{Fixed: "2.0"}),
			rwm("repo", "5.0", &osvschema.Event{Fixed: "6.0"}),
		}

		buckets := partitionMergeableRanges(ranges)
		if len(buckets) != 1 {
			t.Fatalf("expected 1 bucket, got %d", len(buckets))
		}
		if diff := cmp.Diff(ranges, buckets[0], protocmp.Transform()); diff != "" {
			t.Errorf("bucket mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("conflict interleaved with other segments keeps first appearance order", func(t *testing.T) {
		ranges := []models.RangeWithMetadata{
			rwm("repo", "0", &osvschema.Event{LastAffected: "0.9"}),
			rwm("repo", "5.0", &osvschema.Event{Fixed: "6.0"}),
			rwm("repo", "0", &osvschema.Event{Fixed: "1.0"}),
		}

		buckets := partitionMergeableRanges(ranges)
		if len(buckets) != 2 {
			t.Fatalf("expected 2 buckets, got %d", len(buckets))
		}

		// The last_affected segment and the unrelated 5.0->6.0 segment stay together in
		// first-appearance order; the conflicting fixed segment gets its own bucket.
		wantBucket0 := []models.RangeWithMetadata{ranges[0], ranges[1]}
		wantBucket1 := []models.RangeWithMetadata{ranges[2]}
		if diff := cmp.Diff(wantBucket0, buckets[0], protocmp.Transform()); diff != "" {
			t.Errorf("bucket 0 mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(wantBucket1, buckets[1], protocmp.Transform()); diff != "" {
			t.Errorf("bucket 1 mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestMergeRangesAndCreateAffected(t *testing.T) {
	mustMakeDBSpecific := func(m map[string]any) *structpb.Struct {
		ds, err := utility.NewStructpbFromMap(m)
		if err != nil {
			t.Fatalf("failed to make database specific: %v", err)
		}

		return ds
	}

	tests := []struct {
		name            string
		resolvedRanges  []*osvschema.Range
		commits         []models.AffectedCommit
		successfulRepos []string
		want            *osvschema.Affected
	}{
		{
			name: "Merge existing ranges with commits for the same repo",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo1",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				{
					Repo:       "repo1",
					Introduced: "1.1",
				},
				{
					Repo:  "repo1",
					Fixed: "1.2",
				},
			},
			successfulRepos: []string{"repo1"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo1",
						Events: []*osvschema.Event{
							{Introduced: "1.1"},
							{Introduced: "0"},
							{Fixed: "1.0"},
							{Fixed: "1.2"},
						},
						DatabaseSpecific: mustMakeDBSpecific(map[string]any{
							"extracted_events": []any{
								map[string]any{
									"range":  []*osvschema.Event{{Introduced: "1.1"}},
									"source": "REFERENCES",
								},
								map[string]any{
									"range":  []*osvschema.Event{{Fixed: "1.2"}},
									"source": "REFERENCES",
								},
							},
						}),
					},
				},
			},
		},
		{
			name:           "No resolved ranges, only commits",
			resolvedRanges: nil,
			commits: []models.AffectedCommit{
				{
					Repo:       "repo2",
					Introduced: "0",
					Fixed:      "1.0",
				},
			},
			successfulRepos: []string{"repo2"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
						Repo: "repo2",
						Type: osvschema.Range_GIT,
						DatabaseSpecific: mustMakeDBSpecific(map[string]any{
							"extracted_events": []any{
								map[string]any{
									"range":  []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0"}},
									"source": "REFERENCES",
								},
							},
						}),
					},
				},
			},
		},
		{
			name:           "No resolved ranges, multiple commits for multiple repos grouped and sorted",
			resolvedRanges: nil,
			commits: []models.AffectedCommit{
				{
					Repo:       "repo_b",
					Introduced: "0",
				},
				{
					Repo:  "repo_b",
					Fixed: "1.0",
				},
				{
					Repo:       "repo_a",
					Introduced: "0.5",
				},
			},
			successfulRepos: []string{"repo_a", "repo_b"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Events: []*osvschema.Event{
							{Introduced: "0.5"},
						},
						Repo: "repo_a",
						Type: osvschema.Range_GIT,
						DatabaseSpecific: mustMakeDBSpecific(map[string]any{
							"extracted_events": []any{
								map[string]any{
									"range":  []*osvschema.Event{{Introduced: "0.5"}},
									"source": "REFERENCES",
								},
							},
						}),
					},
					{
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
						Repo: "repo_b",
						Type: osvschema.Range_GIT,
						DatabaseSpecific: mustMakeDBSpecific(map[string]any{
							"extracted_events": []any{
								map[string]any{
									"range":  []*osvschema.Event{{Introduced: "0"}},
									"source": "REFERENCES",
								},
								map[string]any{
									"range":  []*osvschema.Event{{Fixed: "1.0"}},
									"source": "REFERENCES",
								},
							},
						}),
					},
				},
			},
		},
		{
			name: "Duplicate events are deduplicated",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo3",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				// duplicate fixed
				{
					Repo:  "repo3",
					Fixed: "1.0",
				},
				// duplicate introduced
				{
					Repo:       "repo3",
					Introduced: "0",
				},
				// new last affected
				{
					Repo:         "repo3",
					LastAffected: "0.5",
				},
			},
			successfulRepos: []string{"repo3"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo3",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
							{LastAffected: "0.5"},
						},
						DatabaseSpecific: mustMakeDBSpecific(map[string]any{
							"extracted_events": []any{
								map[string]any{
									"range":  []*osvschema.Event{{Fixed: "1.0"}},
									"source": "REFERENCES",
								},
								map[string]any{
									"range":  []*osvschema.Event{{Introduced: "0"}},
									"source": "REFERENCES",
								},
								map[string]any{
									"range":  []*osvschema.Event{{LastAffected: "0.5"}},
									"source": "REFERENCES",
								},
							},
						}),
					},
				},
			},
		},
		{
			name: "Commits for repos not in successfulRepos are ignored when resolvedRanges exist",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo4",
					Events: []*osvschema.Event{
						{Introduced: "0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				{
					Repo:       "repo_ignored",
					Introduced: "1.1",
				},
			},
			successfulRepos: []string{"repo4"}, // repo_ignored is absent
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo4",
						Events: []*osvschema.Event{
							{Introduced: "0"},
						},
					},
				},
			},
		},
		{
			name: "Multiple resolved ranges for same repo are merged and commits appended",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo5",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
				{
					Type: osvschema.Range_GIT,
					Repo: "repo5",
					Events: []*osvschema.Event{
						{Introduced: "2.0"},
						{Fixed: "3.0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				{
					Repo:  "repo5",
					Fixed: "4.0",
				},
			},
			successfulRepos: []string{"repo5"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo5",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
							{Introduced: "2.0"},
							{Fixed: "3.0"},
							{Fixed: "4.0"},
						},
						DatabaseSpecific: mustMakeDBSpecific(map[string]any{
							"extracted_events": []any{
								map[string]any{
									"range":  []*osvschema.Event{{Fixed: "4.0"}},
									"source": "REFERENCES",
								},
							},
						}),
					},
				},
			},
		},
		{
			// Same introduced value with mutually exclusive fixed/last_affected
			// boundaries must remain independent ranges in separate Affected entries
			// instead of being concatenated into one invalid OSV range.
			name: "Conflicting fixed and last_affected ranges stay independent",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo6",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
				{
					Type: osvschema.Range_GIT,
					Repo: "repo6",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{LastAffected: "0.9"},
					},
				},
			},
			commits:         nil,
			successfulRepos: []string{"repo6"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo6",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
					},
					{
						Type: osvschema.Range_GIT,
						Repo: "repo6",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{LastAffected: "0.9"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rwms []models.RangeWithMetadata
			for _, r := range tt.resolvedRanges {
				rwms = append(rwms, models.RangeWithMetadata{Range: r})
			}
			var want []*osvschema.Affected
			for _, r := range tt.want.GetRanges() {
				want = append(want, &osvschema.Affected{
					Ranges: []*osvschema.Range{r},
				})
			}
			got := MergeRangesAndCreateAffected(rwms, tt.commits, tt.successfulRepos, &models.ConversionMetrics{})
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("MergeRangesAndCreateAffected() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
