interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md';
}

const colorMap: Record<string, string> = {
  connected: 'bg-green-500/20 text-green-400 border-green-500/30',
  active: 'bg-green-500/20 text-green-400 border-green-500/30',
  COMPLETED: 'bg-green-500/20 text-green-400 border-green-500/30',
  disconnected: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  pending: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  PROCESSING: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  DENIED: 'bg-red-500/20 text-red-400 border-red-500/30',
  HALTED: 'bg-red-500/20 text-red-400 border-red-500/30',
  killed: 'bg-red-500/20 text-red-400 border-red-500/30',
  elevated: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  basic: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  untrusted: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-green-500/20 text-green-400 border-green-500/30',
};

export default function StatusBadge({ status, size = 'sm' }: StatusBadgeProps) {
  const colors = colorMap[status] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span className={`inline-flex items-center rounded-full border font-medium ${colors} ${sizeClasses}`}>
      {status}
    </span>
  );
}
