interface Props {
  label: string;
  description?: string;
  children: React.ReactNode;
  onClick?: () => void;
}

/** One settings row: label (left) + control (right). */
export default function SettingItem({ label, description, children, onClick }: Props) {
  return (
    <div className="setting-item" onClick={onClick} role={onClick ? 'button' : undefined}>
      <div className="setting-item__text">
        <div className="setting-item__label">{label}</div>
        {description && <div className="setting-item__desc">{description}</div>}
      </div>
      <div className="setting-item__control" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}
