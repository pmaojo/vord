import axios from 'axios';

const baseURL = 'https://api.example.com';

export const userClient = axios.create({ baseURL });
