import { BrowserRouter as Router, Navigate, Route, Routes } from 'react-router-dom'
import AppShell from './AppShell'
import FleetPage from './pages/FleetPage'
import GovernancePage from './pages/GovernancePage'
import IncidentQueuePage from './pages/IncidentQueuePage'
import NotFoundPage from './pages/NotFoundPage'
import OverviewPage from './pages/OverviewPage'

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Navigate replace to="/overview" />} />
          <Route path="overview" element={<OverviewPage />} />
          <Route path="incidents" element={<IncidentQueuePage />} />
          <Route path="governance" element={<GovernancePage />} />
          <Route path="fleet" element={<FleetPage />} />
          {/* Catch-all inside the shell, so a bad URL keeps the navigation rather than
              rendering a blank page with no way back. */}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Router>
  )
}
