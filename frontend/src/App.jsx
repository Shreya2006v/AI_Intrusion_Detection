import { useState, useEffect } from 'react'

function App() {
  const [incidents, setIncidents] = useState([])
  const [file, setFile] = useState(null)
  const [isProcessing, setIsProcessing] = useState(false)

  // Fetch historical incidents on load
  useEffect(() => {
    fetchIncidents()
  }, [])

  const fetchIncidents = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/incidents')
      const data = await response.json()
      setIncidents(data)
    } catch (error) {
      console.error("Error fetching incidents:", error)
    }
  }

  const handleFileChange = (e) => {
    if (e.target.files) {
      setFile(e.target.files[0])
    }
  }

  const handleUpload = async () => {
    if (!file) return alert("Please select a log file first.")
    
    setIsProcessing(true)
    const formData = new FormData()
    formData.append("file", file)

    try {
      const response = await fetch('http://127.0.0.1:8000/analyze-file', {
        method: 'POST',
        body: formData,
      })
      const result = await response.json()
      
      if (result.status === "success") {
        alert(`Analysis Complete: ${result.processed_count} threats detected.`)
        fetchIncidents() // Refresh the dashboard data
      } else {
        alert(result.message || "Upload failed.")
      }
    } catch (error) {
      console.error("Error analyzing file:", error)
      alert("Error connecting to the backend.")
    } finally {
      setIsProcessing(false)
      setFile(null)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      <div className="max-w-6xl mx-auto">
        
        {/* Header */}
        <header className="mb-8 border-b border-slate-700 pb-4">
          <h1 className="text-3xl font-bold text-cyan-400">AI-Driven NIDS Dashboard</h1>
          <p className="text-slate-400 mt-2">Autonomous Network Intrusion Detection & Mitigation</p>
        </header>

        {/* Upload Section */}
        <div className="bg-slate-800 p-6 rounded-lg mb-8 shadow-lg border border-slate-700">
          <h2 className="text-xl font-semibold mb-4 text-white">Log Ingestion Engine</h2>
          <div className="flex items-center gap-4">
            <input 
              type="file" 
              onChange={handleFileChange} 
              className="block w-full text-sm text-slate-400
                file:mr-4 file:py-2 file:px-4
                file:rounded-md file:border-0
                file:text-sm file:font-semibold
                file:bg-cyan-500 file:text-white
                hover:file:bg-cyan-600 transition-colors"
            />
            <button 
              onClick={handleUpload}
              disabled={isProcessing}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded-md font-medium transition-colors disabled:opacity-50"
            >
              {isProcessing ? "Analyzing Logs..." : "Run AI Analysis"}
            </button>
          </div>
        </div>

        {/* Threat Intelligence Feed */}
        <div>
          <h2 className="text-2xl font-semibold mb-4 border-b border-slate-700 pb-2">Threat Intelligence Ledger</h2>
          
          {incidents.length === 0 ? (
            <p className="text-slate-500 italic">No historical threats recorded in the database.</p>
          ) : (
            <div className="grid gap-6">
              {incidents.map((incident, index) => (
                <div key={index} className="bg-slate-800 rounded-lg p-6 border-l-4 border-red-500 shadow-md">
                  
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h3 className="text-lg font-bold text-red-400">{incident.anomaly_type} Detected</h3>
                      <p className="text-sm text-slate-400">Target IP: <span className="text-slate-200 font-mono">{incident.source_ip}</span> | Time: {incident.timestamp}</p>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                      incident.severity_level.toLowerCase() === 'critical' ? 'bg-red-900 text-red-200' : 
                      incident.severity_level.toLowerCase() === 'high' ? 'bg-orange-900 text-orange-200' : 
                      'bg-yellow-900 text-yellow-200'
                    }`}>
                      {incident.severity_level}
                    </span>
                  </div>

                  <div className="mb-4">
                    <p className="text-slate-300 text-sm"><strong className="text-white">Threat Profile:</strong> {incident.vulnerability_description}</p>
                    {incident.cve_id && <p className="text-slate-300 text-sm mt-1"><strong className="text-white">Known Vulnerability:</strong> {incident.cve_id}</p>}
                  </div>

                  <div className="bg-slate-900 p-4 rounded-md">
                    <p className="text-xs text-cyan-500 font-bold uppercase mb-2">Generated Mitigation Strategy ({incident.action_required})</p>
                    <code className="text-emerald-400 text-sm font-mono block">
                      {incident.firewall_rule}
                    </code>
                  </div>
                  
                </div>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}

export default App