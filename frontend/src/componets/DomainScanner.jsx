import { useState } from 'react';
import axios from 'axios';

const DomainScanner = () => {
    const [domain, setDomain] = useState('');
    const [scanStatus, setScanStatus] = useState('');
    const [scanResults, setScanResults] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!domain) {
            alert('Please enter a domain');
            return;
        }

        try {
            setScanStatus('Scanning...');
            const response = await axios.post('http://localhost:8080/api/scan', { domain });

            if (response.data.status === 'scanning') {
                setScanStatus(response.data.message);
                getScanResults(domain);
            } else {
                setScanStatus('Error: ' + response.data.message);
            }
        } catch (error) {
            console.error(error);
            setScanStatus('Error initiating scan.');
        }
    };

    const getScanResults = async (domain) => {
        const interval = setInterval(async () => {
            try {
                const response = await axios.get(`http://localhost:8080/api/scan/${domain}`);
                if (response.data.status === 'completed') {
                    clearInterval(interval);
                    setScanResults(response.data);
                    setScanStatus('Scan Completed');
                } else {
                    setScanStatus(response.data.message); // Keep updating status
                }
            } catch (error) {
                clearInterval(interval);
                setScanStatus('Error fetching scan results.');
            }
        }, 3000);
    };

    const downloadFile = async (domain) => {
        try {
            const response = await axios.get(`http://localhost:8080/api/scan/${domain}/file`, {
                responseType: 'blob'
            });
            
            const file = new Blob([response.data], { type: 'text/plain' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(file);
            link.download = `${domain}_status_codes.txt`;
            link.click();
        } catch (error) {
            console.error('Error downloading the file:', error);
        }
    };

    return (
        <div>
            <h1>Domain Scan</h1>
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Enter domain"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                />
                <button type="submit">Start Scan</button>
            </form>

            <h2>{scanStatus}</h2>

            {scanResults && (
                <div>
                    <h3>Subdomains:</h3>
                    <ul>
                        {scanResults.subdomains && scanResults.subdomains.map((sub, idx) => (
                            <li key={idx}>{sub.subdomain}</li>
                        ))}
                    </ul>

                    <h3>Open Ports:</h3>
                    <ul>
                        {scanResults.openPorts && scanResults.openPorts.map((port, idx) => (
                            <li key={idx}>{port.port} - {port.status}</li>
                        ))}
                    </ul>

                    <h3>HTTPx Results:</h3>
                    <ul>
                        {scanResults.httpxResults && scanResults.httpxResults.map((result, idx) => (
                            <li key={idx}>
                                {result.subdomain}:{result.port} - {result.status}
                            </li>
                        ))}
                    </ul>

                    <button onClick={() => downloadFile(domain)}>Download Status Code File</button>
                </div>
            )}
        </div>
    );
};

export default DomainScanner;
