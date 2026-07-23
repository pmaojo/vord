import React, { useEffect, useMemo, useState } from 'react';
import { useAuditLog, useRules } from '../../../lib/queries';
import { upsertQualityProfile, ApiProfileActivation } from '../../../lib/api';
import { BookOpen, Plus, Trash2, Loader2, Save, AlertCircle } from 'lucide-react';

const SEVERITIES = ['info', 'minor', 'major', 'critical', 'blocker'];

interface ProfileDraft {
  name: string;
  activations: ApiProfileActivation[];
}

/// No "list profiles" endpoint exists (upsert + audit-log only, same as
/// gates) — reconstruct the known set from the most recent `after` snapshot
/// recorded per profile name.
function profilesFromAuditLog(entries: { entity_id: string; after: unknown; at: string }[]): ProfileDraft[] {
  const byName = new Map<string, ProfileDraft & { at: string }>();
  for (const entry of entries) {
    const existing = byName.get(entry.entity_id);
    if (!existing || entry.at > existing.at) {
      byName.set(entry.entity_id, {
        name: entry.entity_id,
        activations: Array.isArray(entry.after) ? (entry.after as ApiProfileActivation[]) : [],
        at: entry.at,
      });
    }
  }
  return Array.from(byName.values()).sort((a, b) => a.name.localeCompare(b.name));
}

export const QualityProfilesView: React.FC = () => {
  const { data: auditLog, isLoading, refetch } = useAuditLog('quality_profile');
  const { data: rules } = useRules();
  const knownProfiles = useMemo(() => profilesFromAuditLog(auditLog?.items ?? []), [auditLog]);

  const [drafts, setDrafts] = useState<ProfileDraft[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newRule, setNewRule] = useState('');
  const [newSeverity, setNewSeverity] = useState('major');
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (knownProfiles.length > 0 && drafts.length === 0) {
      setDrafts(knownProfiles);
      setSelectedName(knownProfiles[0].name);
    }
  }, [knownProfiles, drafts.length]);

  useEffect(() => {
    if (!newRule && rules && rules.length > 0) {
      setNewRule(rules[0].id);
    }
  }, [rules, newRule]);

  const selectedProfile = drafts.find((p) => p.name === selectedName) ?? drafts[0];

  const handleCreateProfile = () => {
    const name = prompt('Enter a name for the new Quality Profile:');
    if (!name) return;
    const draft: ProfileDraft = { name: name.trim(), activations: [] };
    setDrafts((prev) => [...prev, draft]);
    setSelectedName(draft.name);
  };

  const handleAddActivation = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProfile || !newRule) return;
    const activation: ApiProfileActivation = { rule: newRule, severity: newSeverity };
    setDrafts((prev) =>
      prev.map((p) =>
        p.name === selectedProfile.name
          ? { ...p, activations: [...p.activations.filter((a) => a.rule !== newRule), activation] }
          : p
      )
    );
    setIsAddOpen(false);
    setSaveState('idle');
  };

  const handleRemoveActivation = (rule: string) => {
    if (!selectedProfile) return;
    setDrafts((prev) =>
      prev.map((p) =>
        p.name === selectedProfile.name
          ? { ...p, activations: p.activations.filter((a) => a.rule !== rule) }
          : p
      )
    );
    setSaveState('idle');
  };

  const handleSave = async () => {
    if (!selectedProfile) return;
    setSaveState('saving');
    setSaveError(null);
    try {
      await upsertQualityProfile(selectedProfile.name, selectedProfile.activations);
      setSaveState('saved');
      refetch();
    } catch (err) {
      setSaveState('error');
      setSaveError(err instanceof Error ? err.message : 'Failed to save profile');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2">
            <BookOpen className="w-7 h-7 text-sky-600" />
            <span>Quality Profiles</span>
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            A profile activates a chosen severity for a subset of the rule catalog. Saved through{' '}
            <code className="font-mono">PUT /api/quality-profiles/{'{name}'}</code>.
          </p>
        </div>

        <button
          onClick={handleCreateProfile}
          className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-xl shadow-xs transition-colors flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>Create Profile</span>
        </button>
      </div>

      {isLoading && drafts.length === 0 && (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-12 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading profiles from the audit trail...
        </div>
      )}

      {!isLoading && drafts.length === 0 && (
        <div className="bg-white rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500">
          No quality profiles have been saved yet. Create one to get started.
        </div>
      )}

      {drafts.length > 0 && selectedProfile && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          <div className="lg:col-span-1 bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-2">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 mb-2">Profiles</div>
            {drafts.map((profile) => (
              <button
                key={profile.name}
                onClick={() => {
                  setSelectedName(profile.name);
                  setSaveState('idle');
                }}
                className={`w-full text-left p-3 rounded-xl font-bold text-xs transition-all ${
                  selectedProfile.name === profile.name
                    ? 'bg-sky-600 text-white shadow-xs'
                    : 'text-slate-800 hover:bg-slate-100'
                }`}
              >
                {profile.name}
              </button>
            ))}
          </div>

          <div className="lg:col-span-3 space-y-6">
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4 mb-6">
                <div>
                  <h2 className="text-xl font-black text-slate-900">{selectedProfile.name}</h2>
                  <p className="text-xs text-slate-500 mt-1">
                    {selectedProfile.activations.length} rule activation(s).
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setIsAddOpen(true)}
                    className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 font-bold text-xs rounded-lg transition-colors border border-slate-300 flex items-center gap-1.5"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    Activate Rule
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={saveState === 'saving'}
                    className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5"
                  >
                    {saveState === 'saving' ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Save className="w-3.5 h-3.5" />
                    )}
                    {saveState === 'saving' ? 'Saving...' : 'Save Profile'}
                  </button>
                </div>
              </div>

              {saveState === 'saved' && (
                <div className="mb-4 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-bold rounded-lg px-3 py-2">
                  Saved. Recorded in the audit log as profile.updated.
                </div>
              )}
              {saveState === 'error' && (
                <div className="mb-4 bg-rose-50 border border-rose-200 text-rose-800 text-xs font-bold rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {saveError}
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                      <th className="py-3 px-4">Rule</th>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-xs font-medium">
                    {selectedProfile.activations.length === 0 && (
                      <tr>
                        <td colSpan={3} className="py-6 text-center text-slate-400 font-mono text-xs">
                          No rules activated yet.
                        </td>
                      </tr>
                    )}
                    {selectedProfile.activations.map((activation) => (
                      <tr key={activation.rule} className="hover:bg-slate-50">
                        <td className="py-3 px-4 font-mono font-bold text-slate-900">{activation.rule}</td>
                        <td className="py-3 px-4">
                          <span className="bg-slate-100 text-slate-700 text-[10px] font-bold px-2 py-0.5 rounded border border-slate-200 uppercase">
                            {activation.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => handleRemoveActivation(activation.rule)}
                            className="p-1 text-slate-400 hover:text-rose-600 rounded"
                            title="Remove activation"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {isAddOpen && selectedProfile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-md w-full p-6 animate-in fade-in zoom-in-95 duration-150">
            <h3 className="text-lg font-bold text-slate-900 border-b border-slate-100 pb-3 mb-4">Activate Rule</h3>

            <form onSubmit={handleAddActivation} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">Rule</label>
                <select
                  value={newRule}
                  onChange={(e) => setNewRule(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-mono"
                >
                  {(rules ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.id}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Severity
                </label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-medium"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-4 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setIsAddOpen(false)}
                  className="px-4 py-2 text-xs font-bold text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-lg shadow-xs"
                >
                  Activate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
