import { Link, useLocation } from 'react-router-dom'
import { EmptyState, PageHeader } from '../components/ui'

export default function NotFoundPage() {
  const { pathname } = useLocation()

  return (
    <div className="space-y-6">
      <PageHeader title="Not found" />
      <EmptyState
        title={`No page at ${pathname}`}
        detail={
          <>
            Pick a destination from the sidebar, or{' '}
            <Link to="/overview" className="text-primary underline">
              return to the overview
            </Link>
            .
          </>
        }
      />
    </div>
  )
}
