import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Devices from './pages/Devices'
import AssetDetail from './pages/AssetDetail'
import History from './pages/History'
import Services from './pages/Services'
import Findings from './pages/Findings'
import Vulnerabilities from './pages/Vulnerabilities'
import ScanActivity from './pages/ScanActivity'
import ScanSessions from './pages/ScanSessions'
import Placeholder from './pages/Placeholder'
import Login from './pages/Login'
import Signup from './pages/Signup'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route
        path="/*"
        element={
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/devices/:assetId" element={<AssetDetail />} />
              <Route path="/history" element={<History />} />
              <Route path="/services" element={<Services />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/discovery" element={<ScanActivity />} />
              <Route path="/sessions" element={<ScanSessions />} />
              <Route path="/settings" element={<Placeholder title="Settings" />} />
            </Routes>
          </Layout>
        }
      />
    </Routes>
  )
}
