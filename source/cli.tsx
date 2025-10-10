#!/usr/bin/env node

import {render} from 'ink';
import { getBanner } from './components/header.js';
import App from './app.js';

console.log(getBanner());

render(<App />);
