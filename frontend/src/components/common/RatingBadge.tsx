import React from 'react';
import { Rating } from '../../types';
import { cn } from '../../lib/utils';

interface RatingBadgeProps {
  rating: Rating;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  showLabel?: boolean;
}

const RATING_COLORS: Record<Rating, { bg: string; text: string; label: string }> = {
  A: { bg: 'bg-[#00aa00]', text: 'text-white', label: 'A - Passed' },
  B: { bg: 'bg-[#b0ca12]', text: 'text-white', label: 'B - Minor' },
  C: { bg: 'bg-[#ed7d20]', text: 'text-white', label: 'C - Moderate' },
  D: { bg: 'bg-[#e76120]', text: 'text-white', label: 'D - Major' },
  E: { bg: 'bg-[#d4333f]', text: 'text-white', label: 'E - Critical' },
};

const SIZE_CLASSES = {
  sm: 'w-4 h-4 text-[10px] font-bold rounded-sm',
  md: 'w-6 h-6 text-xs font-bold rounded',
  lg: 'w-8 h-8 text-base font-extrabold rounded-md',
};

export const RatingBadge: React.FC<RatingBadgeProps> = ({
  rating,
  size = 'md',
  className,
  showLabel = false,
}) => {
  const config = RATING_COLORS[rating] || RATING_COLORS.A;

  return (
    <div className="inline-flex items-center gap-2" title={config.label}>
      <span
        className={cn(
          'inline-flex items-center justify-center font-mono shadow-xs transition-transform',
          config.bg,
          config.text,
          SIZE_CLASSES[size],
          className
        )}
      >
        {rating}
      </span>
      {showLabel && <span className="text-xs font-medium text-slate-600">{config.label}</span>}
    </div>
  );
};
