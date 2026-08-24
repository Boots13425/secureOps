import Sidebar from './Sidebar'
import Topbar from './Topbar'
import { useScanSocket } from '../hooks/useScanSocket'

export default function Layout({ children }) {
  useScanSocket()

  return (
    <div className="min-h-screen">
      <Sidebar />
      <Topbar />
      <main
        className="app-main pt-[calc(var(--topbar-h)+28px)] pb-10 px-7"
        style={{ marginLeft: 'var(--sidebar-w)' }}
      >
        {children}
      </main>
    </div>
  )
}
