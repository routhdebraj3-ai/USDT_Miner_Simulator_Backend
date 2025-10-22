const axios = require('axios');

// Get your free token from https://ipinfo.io/signup
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;

async function fetchLocation(ip) {
  try {
    if (!ip) return null;

    // Clean up IPv6 localhost (::1)
    if (ip === '::1' || ip === '127.0.0.1') {
      return {
        ip,
        city: null,
        region: null,
        country: null,
        latitude: null,
        longitude: null,
      };
    }

    // 📡 Call ipinfo.io API
    const response = await axios.get(`https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`);
    const data = response.data;

    // ipinfo returns location as a comma-separated string: "lat,lon"
    let latitude = null;
    let longitude = null;
    if (data.loc) {
      [latitude, longitude] = data.loc.split(',').map(Number);
    }

    return {
      ip,
      city: data.city || null,
      region: data.region || null,
      country: data.country || null,
      latitude,
      longitude,
    };
  } catch (err) {
    console.error('Error fetching IP location:', err.message);
    return null;
  }
}

module.exports = fetchLocation;
