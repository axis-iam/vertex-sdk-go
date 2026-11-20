import React, { useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ConnectedAppSessionTransport } from '@axis-iam/vertex'
import { IamProvider, SignIn, useAuth, useServerSession } from '@axis-iam/vertex-react'

async function start() {
  const response = await fetch('/example-config', { credentials: 'same-origin', cache: 'no-store' })
  if (!response.ok) throw new Error('Example configuration unavailable')
  const config = await response.json()
  const transport = new ConnectedAppSessionTransport({ origin: config.origin, basePath: '/auth' })

  function App() {
    const { isLoaded, isAuthenticated, initializationError, user, logout } = useAuth()
    const { view } = useServerSession()
    const [custom, setCustom] = useState(false)
    const [result, setResult] = useState('')
    const [error, setError] = useState('')
    async function documents() {
      const response = await fetch('/api/documents', { credentials: 'same-origin', cache: 'no-store' })
      if (!response.ok) { setError(`Business request failed (${response.status})`); return }
      setResult(JSON.stringify(await response.json()))
    }
    async function createDocument() {
      const response = await fetch('/api/documents', {
        method: 'POST', credentials: 'same-origin', headers: {
          'Content-Type': 'application/json',
          'Origin': window.location.origin,
          'X-CSRF-Token': view?.csrfToken ?? '',
        }, body: JSON.stringify({ title: 'Example document' }),
      })
      if (!response.ok) { setError(`Business write failed (${response.status})`); return }
      setResult(JSON.stringify(await response.json()))
    }
    async function hosted() {
      try {
        await transport.request({ action: 'bootstrap' })
        window.location.assign('/auth/login')
      } catch { setError('Unable to start sign in') }
    }
    return <main style={{ maxWidth: 640, margin: '3rem auto', padding: '0 1rem', fontFamily: 'system-ui' }}>
      <h1>Application session</h1>
      {!isLoaded ? <p>Loading session…</p> : initializationError ? <p role="alert">Session unavailable</p> :
        isAuthenticated ? <>
          <p>Signed in as {user.email ?? user.id}</p>
        <button onClick={documents}>Read documents</button>{' '}
        <button onClick={createDocument}>Create document</button>{' '}
          <button onClick={() => logout().catch(() => setError('Logout could not be confirmed'))}>Sign out</button>
          <pre>{result}</pre>
        </> : <>
          <button onClick={hosted}>Sign in with Hosted</button>{' '}
          <button onClick={() => setCustom(value => !value)}>Custom sign in</button>
          {custom && <SignIn mode="embedded" onSuccess={() => setCustom(false)} />}
        </>}
      {error && <p role="alert">{error}</p>}
    </main>
  }

  // Match the Go host's clean ReturnTo destination after its callback.
  createRoot(document.getElementById('root')).render(
    <IamProvider {...config} sessionMode="server_session" sessionLoginUri={`${config.origin}/auth/login`}
      sessionProviderReturnUri={`${config.origin}/`} sessionTransport={transport}>
      <App />
    </IamProvider>,
  )
}
start().catch(() => {
  document.getElementById('root').textContent = 'Application configuration unavailable'
})
