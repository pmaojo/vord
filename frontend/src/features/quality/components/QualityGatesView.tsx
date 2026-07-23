import React, { useEffect, useMemo, useState } from 'react';
import { useAuditLog } from '../../../lib/queries';
import { upsertQualityGate, ApiGateCondition } from '../../../lib/api';
import { ShieldCheck, Plus, Trash2, Loader2, Save, AlertCircle } from 'lucide-react';

const KNOWN_METRICS = ['blocker_issues', 'critical_issues', 'parse_failures', 'coverage'];

interface GateDraft {
  name: string;
  conditions: ApiGateCondition[];
}

/// There is no "list gates" endpoint (Fase 4 is upsert + audit-log only), so
/// the known gate set is reconstructed from the audit trail: one entry per
/// name, keeping the most recent `after` snapshot as that gate's current state.
function gatesFromAuditLog(entries: { entity_id: string; after: unknown; at: string }[]): GateDraft[] {
  const byName = new Map<string, GateDraft & { at: string }>();
  for (const entry of entries) {
    const existing = byName.get(entry.entity_id);
    if (!existing || entry.at > existing.at) {
      byName.set(entry.entity_id, {
        name: entry.entity_id,
        conditions: Array.isArray(entry.after) ? (entry.after as ApiGateCondition[]) : [],
        at: entry.at,
      });
    }
  }
  return Array.from(byName.values()).sort((a, b) => a.name.localeCompare(b.name));
}

export const QualityGatesView: React.FC = () => {
  const { data: auditLog, isLoading, refetch } = useAuditLog('quality_gate');
  const knownGates = useMemo(() => gatesFromAuditLog(auditLog?.items ?? []), [auditLog]);

  const [drafts, setDrafts] = useState<GateDraft[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [isAddConditionOpen, setIsAddConditionOpen] = useState(false);
  const [newMetric, setNewMetric] = useState('coverage');
  const [newOp, setNewOp] = useState<'gt' | 'lt'>('lt');
  const [newThreshold, setNewThreshold] = useState('80');
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (knownGates.length > 0 && drafts.length === 0) {
      setDrafts(knownGates);
      setSelectedName(knownGates[0].name);
    }
  }, [knownGates, drafts.length]);

  const selectedGate = drafts.find((g) => g.name === selectedName) ?? drafts[0];

  const handleCreateGate = () => {
    const name = prompt('Enter a name for the new Quality Gate (lowercase, hyphens ok):');
    if (!name) return;
    const draft: GateDraft = { name: name.trim(), conditions: [] };
    setDrafts((prev) => [...prev, draft]);
    setSelectedName(draft.name);
  };

  const handleAddCondition = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedGate) return;
    const threshold = Number(newThreshold);
    if (Number.isNaN(threshold)) return;
    const condition: ApiGateCondition = { metric: newMetric, operator: newOp, threshold };
    setDrafts((prev) =>
      prev.map((g) => (g.name === selectedGate.name ? { ...g, conditions: [...g.conditions, condition] } : g))
    );
    setIsAddConditionOpen(false);
    setSaveState('idle');
  };

  const handleDeleteCondition = (index: number) => {
    if (!selectedGate) return;
    setDrafts((prev) =>
      prev.map((g) =>
        g.name === selectedGate.name ? { ...g, conditions: g.conditions.filter((_, i) => i !== index) } : g
      )
    );
    setSaveState('idle');
  };

  const handleSave = async () => {
    if (!selectedGate) return;
    setSaveState('saving');
    setSaveError(null);
    try {
      await upsertQualityGate(selectedGate.name, selectedGate.conditions);
      setSaveState('saved');
      refetch();
    } catch (err) {
      setSaveState('error');
      setSaveError(err instanceof Error ? err.message : 'Failed to save gate');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2">
            <ShieldCheck className="w-7 h-7 text-sky-600" />
            <span>Quality Gates Management</span>
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Edits are saved through <code className="font-mono">PUT /api/quality-gates/{'{name}'}</code> and
            recorded to the audit log — there is no per-project assignment yet, just the named condition sets
            themselves.
          </p>
        </div>

        <button
          onClick={handleCreateGate}
          className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-xl shadow-xs transition-colors flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>Create Quality Gate</span>
        </button>
      </div>

      {isLoading && drafts.length === 0 && (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-12 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading gates from the audit trail...
        </div>
      )}

      {!isLoading && drafts.length === 0 && (
        <div className="bg-white rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500">
          No quality gates have been saved yet. Create one to get started.
        </div>
      )}

      {drafts.length > 0 && selectedGate && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          <div className="lg:col-span-1 bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-2">
            <div className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 mb-2">
              Configured Gates
            </div>
            {drafts.map((gate) => (
              <button
                key={gate.name}
                onClick={() => {
                  setSelectedName(gate.name);
                  setSaveState('idle');
                }}
                className={`w-full text-left p-3 rounded-xl font-bold text-xs transition-all ${
                  selectedGate.name === gate.name
                    ? 'bg-sky-600 text-white shadow-xs'
                    : 'text-slate-800 hover:bg-slate-100'
                }`}
              >
                {gate.name}
              </button>
            ))}
          </div>

          <div className="lg:col-span-3 space-y-6">
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4 mb-6">
                <div>
                  <h2 className="text-xl font-black text-slate-900">{selectedGate.name}</h2>
                  <p className="text-xs text-slate-500 mt-1">
                    Enforces {selectedGate.conditions.length} threshold rule(s).
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setIsAddConditionOpen(true)}
                    className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 font-bold text-xs rounded-lg transition-colors border border-slate-300 flex items-center gap-1.5"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    Add Condition
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
                    {saveState === 'saving' ? 'Saving...' : 'Save Gate'}
                  </button>
                </div>
              </div>

              {saveState === 'saved' && (
                <div className="mb-4 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-bold rounded-lg px-3 py-2">
                  Saved. Recorded in the audit log as gate.updated.
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
                      <th className="py-3 px-4">Metric</th>
                      <th className="py-3 px-4">Operator</th>
                      <th className="py-3 px-4">Threshold</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-xs font-medium">
                    {selectedGate.conditions.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-slate-400 font-mono text-xs">
                          No conditions yet — add one above.
                        </td>
                      </tr>
                    )}
                    {selectedGate.conditions.map((cond, idx) => (
                      <tr key={`${cond.metric}-${idx}`} className="hover:bg-slate-50">
                        <td className="py-3 px-4 font-mono font-bold text-slate-900">{cond.metric}</td>
                        <td className="py-3 px-4 font-mono font-bold text-slate-600">
                          {cond.operator === 'lt' ? 'is less than (<)' : 'is greater than (>)'}
                        </td>
                        <td className="py-3 px-4 font-mono font-bold text-rose-600">{cond.threshold}</td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => handleDeleteCondition(idx)}
                            className="p-1 text-slate-400 hover:text-rose-600 rounded"
                            title="Delete condition"
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

      {isAddConditionOpen && selectedGate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-md w-full p-6 animate-in fade-in zoom-in-95 duration-150">
            <h3 className="text-lg font-bold text-slate-900 border-b border-slate-100 pb-3 mb-4">
              Add Quality Gate Condition
            </h3>

            <form onSubmit={handleAddCondition} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Metric
                </label>
                <select
                  value={newMetric}
                  onChange={(e) => setNewMetric(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-medium"
                >
                  {KNOWN_METRICS.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Operator
                </label>
                <select
                  value={newOp}
                  onChange={(e) => setNewOp(e.target.value as 'gt' | 'lt')}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-medium"
                >
                  <option value="lt">Is less than (&lt;)</option>
                  <option value="gt">Is greater than (&gt;)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Threshold
                </label>
                <input
                  type="number"
                  step="any"
                  value={newThreshold}
                  onChange={(e) => setNewThreshold(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-mono font-bold"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-4 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setIsAddConditionOpen(false)}
                  className="px-4 py-2 text-xs font-bold text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-lg shadow-xs"
                >
                  Add Condition
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
