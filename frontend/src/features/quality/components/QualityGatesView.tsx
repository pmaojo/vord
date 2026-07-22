import React, { useState } from 'react';
import { MOCK_QUALITY_GATES } from '../../../testing/mock-data';
import { QualityGate, QualityGateCondition } from '../../../types';
import { ShieldCheck, Plus, Trash2, Edit2, CheckCircle2, Star, AlertCircle, X, ChevronRight } from 'lucide-react';

export const QualityGatesView: React.FC = () => {
  const [gates, setGates] = useState<QualityGate[]>(MOCK_QUALITY_GATES);
  const [selectedGateId, setSelectedGateId] = useState<string>(MOCK_QUALITY_GATES[0].id);

  const [isAddConditionOpen, setIsAddConditionOpen] = useState(false);
  const [newMetric, setNewMetric] = useState('coverage');
  const [newOp, setNewOp] = useState<'LT' | 'GT'>('LT');
  const [newThreshold, setNewThreshold] = useState('80.0');
  const [newPeriod, setNewPeriod] = useState<'NEW_CODE' | 'OVERALL'>('NEW_CODE');

  const selectedGate = gates.find((g) => g.id === selectedGateId) || gates[0];

  const handleAddCondition = (e: React.FormEvent) => {
    e.preventDefault();
    const newCond: QualityGateCondition = {
      id: `cond-${Date.now()}`,
      metric: newMetric,
      metricName: newMetric === 'coverage' ? 'Coverage (%)' : 'Duplicated Lines (%)',
      op: newOp,
      errorThreshold: newThreshold,
      period: newPeriod,
    };

    setGates((prev) =>
      prev.map((g) => (g.id === selectedGate.id ? { ...g, conditions: [...g.conditions, newCond] } : g))
    );
    setIsAddConditionOpen(false);
  };

  const handleDeleteCondition = (condId: string) => {
    setGates((prev) =>
      prev.map((g) =>
        g.id === selectedGate.id
          ? { ...g, conditions: g.conditions.filter((c) => c.id !== condId) }
          : g
      )
    );
  };

  const handleSetDefault = (gateId: string) => {
    setGates((prev) =>
      prev.map((g) => ({ ...g, isDefault: g.id === gateId }))
    );
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
            Quality Gates define the release policy conditions that project builds must meet before deployment.
          </p>
        </div>

        <button
          onClick={() => {
            const name = prompt('Enter new Quality Gate name:');
            if (name) {
              const newGate: QualityGate = {
                id: `gate-${Date.now()}`,
                name,
                isDefault: false,
                conditions: [],
              };
              setGates([...gates, newGate]);
              setSelectedGateId(newGate.id);
            }
          }}
          className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-xl shadow-xs transition-colors flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>Create Quality Gate</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Quality Gates List Sidebar */}
        <div className="lg:col-span-1 bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-2">
          <div className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 mb-2">
            Configured Gates
          </div>
          {gates.map((gate) => (
            <button
              key={gate.id}
              onClick={() => setSelectedGateId(gate.id)}
              className={`w-full text-left p-3 rounded-xl font-bold text-xs transition-all flex items-center justify-between ${
                selectedGate.id === gate.id
                  ? 'bg-sky-600 text-white shadow-xs'
                  : 'text-slate-800 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2">
                <span>{gate.name}</span>
                {gate.isDefault && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase ${selectedGate.id === gate.id ? 'bg-sky-700 text-sky-100' : 'bg-slate-200 text-slate-700'}`}>
                    Default
                  </span>
                )}
              </div>
              <ChevronRight className="w-4 h-4 opacity-60" />
            </button>
          ))}
        </div>

        {/* Selected Gate Conditions Details */}
        <div className="lg:col-span-3 space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4 mb-6">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-black text-slate-900">{selectedGate.name}</h2>
                  {selectedGate.isDefault && (
                    <span className="text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full flex items-center gap-1">
                      <Star className="w-3 h-3 fill-emerald-600" />
                      Default Gate
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Enforces {selectedGate.conditions.length} threshold rules during analysis.
                </p>
              </div>

              <div className="flex items-center gap-2">
                {!selectedGate.isDefault && (
                  <button
                    onClick={() => handleSetDefault(selectedGate.id)}
                    className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 font-bold text-xs rounded-lg transition-colors border border-slate-300"
                  >
                    Set as Default
                  </button>
                )}

                <button
                  onClick={() => setIsAddConditionOpen(true)}
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Condition
                </button>
              </div>
            </div>

            {/* Conditions Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    <th className="py-3 px-4">Metric</th>
                    <th className="py-3 px-4">Scope</th>
                    <th className="py-3 px-4">Operator</th>
                    <th className="py-3 px-4">Error Threshold</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs font-medium">
                  {selectedGate.conditions.map((cond) => (
                    <tr key={cond.id} className="hover:bg-slate-50">
                      <td className="py-3 px-4 font-bold text-slate-900">{cond.metricName}</td>
                      <td className="py-3 px-4">
                        <span className="bg-slate-100 text-slate-700 text-[10px] font-bold px-2 py-0.5 rounded border border-slate-200 uppercase">
                          {cond.period || 'NEW_CODE'}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-slate-600">
                        {cond.op === 'LT' ? 'is less than (<)' : 'is greater than (>)'}
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-rose-600">{cond.errorThreshold}</td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleDeleteCondition(cond.id)}
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

      {/* Add Condition Modal */}
      {isAddConditionOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-md w-full p-6 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3 mb-4">
              <h3 className="text-lg font-bold text-slate-900">Add Quality Gate Condition</h3>
              <button onClick={() => setIsAddConditionOpen(false)} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

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
                  <option value="coverage">Coverage (%)</option>
                  <option value="duplicated_lines_density">Duplicated Lines (%)</option>
                  <option value="bugs">New Bugs Count</option>
                  <option value="vulnerabilities">New Vulnerabilities Count</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Operator
                </label>
                <select
                  value={newOp}
                  onChange={(e) => setNewOp(e.target.value as any)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-medium"
                >
                  <option value="LT">Is less than (&lt;)</option>
                  <option value="GT">Is greater than (&gt;)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Error Threshold
                </label>
                <input
                  type="text"
                  value={newThreshold}
                  onChange={(e) => setNewThreshold(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-2 text-xs font-mono font-bold"
                  placeholder="e.g. 80.0"
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
                  Save Condition
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
