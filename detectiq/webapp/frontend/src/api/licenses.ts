import axios from 'axios';

const licenseClient = axios.create({
  baseURL: '/',
  headers: {
    'Content-Type': 'text/plain',
  }
});

export const getLicenseContent = async (ruleType: string): Promise<string> => {
  try {
    const response = await fetch(`/api/licenses/${ruleType}`, {
      headers: {
        'Accept': 'text/plain'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to fetch ${ruleType} license: ${response.statusText}`);
    }
    
    return response.text();
  } catch (error) {
    console.error(`Error fetching ${ruleType} license:`, error);
    throw error;
  }
}; 