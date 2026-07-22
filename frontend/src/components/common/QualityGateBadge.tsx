import React from 'react';
import { QualityGateStatus } from '../../types';
import { CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { cn } from '../../lib/utils';

interface QualityGateBadgeProps {
  status: QualityGateStatus;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  showIcon?: boolean;
}

export const QualityGateBadge: React.FC<QualityGateBadgeProps> = ({
  status,
  size = 'md',
  className,
  showIcon = true,
}) => {
  if (status === 'PASSED') {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md',
          size === 'sm' && 'px-2 py-0.5 text-xs',
          size === 'md' && 'px-2.5 py-1 text-xs',
          size === 'lg' && 'px-3.5 py-1.5 text-sm',
          className
        )}
      >
        {showIcon && <CheckCircle2 className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />}
        <span>PASSED</span>
      </span>
    );
  }

  if (status === 'WARN') {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 font-semibold text-amber-700 bg-amber-50 border border-amber-200 rounded-md',
          size === 'sm' && 'px-2 py-0.5 text-xs',
          size === 'md' && 'px-2.5 py-1 text-xs',
          size === 'lg' && 'px-3.5 py-1.5 text-sm',
          className
        )}
      >
        {showIcon && <AlertTriangle className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />}
        <span>WARNING</span>
      </span>
    );
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-semibold text-rose-700 bg-rose-50 border border-rose-200 rounded-md',
        size === 'sm' && 'px-2 py-0.5 text-xs',
        size === 'md' && 'px-2.5 py-1 text-xs',
        size === 'lg' && 'px-3.5 py-1.5 text-sm',
        className
      )}
    >
      {showIcon && <XCircle className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />}
      <span>FAILED</span>
    </span>
  );
};
