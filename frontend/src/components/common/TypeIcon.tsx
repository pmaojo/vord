import React from 'react';
import { IssueType } from '../../types';
import { Bug, ShieldCheck, Wrench, Flame } from 'lucide-react';
import { cn } from '../../lib/utils';

interface TypeIconProps {
  type: IssueType;
  className?: string;
  showText?: boolean;
}

export const TypeIcon: React.FC<TypeIconProps> = ({ type, className, showText = false }) => {
  const renderIcon = () => {
    switch (type) {
      case 'BUG':
        return <Bug className={cn('w-4 h-4 text-red-600', className)} title="Bug" />;
      case 'VULNERABILITY':
        return <ShieldCheck className={cn('w-4 h-4 text-rose-600', className)} title="Vulnerability" />;
      case 'CODE_SMELL':
        return <Wrench className={cn('w-4 h-4 text-amber-600', className)} title="Code Smell" />;
      case 'SECURITY_HOTSPOT':
        return <Flame className={cn('w-4 h-4 text-orange-500', className)} title="Security Hotspot" />;
      default:
        return null;
    }
  };

  const getLabel = () => {
    switch (type) {
      case 'BUG': return 'Bug';
      case 'VULNERABILITY': return 'Vulnerability';
      case 'CODE_SMELL': return 'Code Smell';
      case 'SECURITY_HOTSPOT': return 'Security Hotspot';
    }
  };

  return (
    <span className="inline-flex items-center gap-1.5 font-medium text-xs text-slate-700">
      {renderIcon()}
      {showText && <span>{getLabel()}</span>}
    </span>
  );
};
