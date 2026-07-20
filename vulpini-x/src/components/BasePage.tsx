interface Props {
  title: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}

/** The uniform page skeleton: header (title left, actions right) + body. */
export default function BasePage({ title, actions, children }: Props) {
  return (
    <div className="content">
      <div className="page">
        <header className="page__header">
          <h1 className="page__title">{title}</h1>
          {actions && <div className="page__actions">{actions}</div>}
        </header>
        <div className="page__body">{children}</div>
      </div>
    </div>
  );
}
