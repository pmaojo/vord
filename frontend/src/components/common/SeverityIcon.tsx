import React from 'react';
import { IssueSeverity } from '../../types';
import { Flame, ShieldAlert, ArrowUpCircle, ArrowDownCircle, Info } from 'lucide-react';
import { cn } from '../../lib/utils';

interface SeverityIconProps {
  severity: IssueSeverity;
  className?: string;
  showText?: boolean;
}

export const SeverityIcon: React.FC<SeverityIconProps> = ({ severity, className, showText = false }) => {
  const renderIcon = () => {
    switch (severity) {
      case 'BLOCKER':
        return <Flame className={cn('w-4 h-4 text-red-600 fill-red-100', className)} title="Blocker" />;
      case 'CRITICAL':
        return <ShieldAlert className={cn('w-4 h-4 text-rose-600', className)} title="Critical" />;
      case 'MAJOR':
        return <ArrowUpCircle className={cn('w-4 h-4 text-orange-500', className)} title="Major" />;
      case 'MINOR':
        return <ArrowDownCircle className={cn('w-4 h-4 text-sky-500', className)} title="Minor" />;
      case 'INFO':
        return <Info className={cn('w-4 h-4 text-slate-400', className)} title="Info" />;
      default:
        return null;
    }
  };

  return (
    <span className="inline-flex items-center gap-1.5 font-medium text-xs text-slate-700">
      {renderIcon()}
      {showText && <span className="capitalize">{severity.toLowerCase()}</span>}
    </span>
  );
};
