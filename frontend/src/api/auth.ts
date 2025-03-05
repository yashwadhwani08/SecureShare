import axios from 'axios';

const API_URL = 'http://localhost:8000/api/';

export const login = async (email: string, password: string) => {
  const response = await axios.post(`${API_URL}token/`, { email, password });
  localStorage.setItem('access_token', response.data.access);
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('access_token');
};
