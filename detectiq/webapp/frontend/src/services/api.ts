const API_BASE_URL = '/api';

export const RuleAPI = {
    createWithLLM: async (data: any) => {
        const response = await fetch(`${API_BASE_URL}/rules/create_with_llm/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return response.json();
    },
    // ... other methods ...
}; 