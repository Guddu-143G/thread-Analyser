export default function SeverityBadge({ severity }) {
  const cls = `severity-badge severity-${severity}`
  return <span className={cls}>{severity}</span>
}
