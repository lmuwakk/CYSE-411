# Final Exam – Version 1  
GMU Smart Scooter Charging System

## Overview
Company **GMU Smart Mobility Solutions** is developing an innovative Smart Scooter Charging System designed to modernize and scale micromobility infrastructure in major cities. The platform uses a Node.js backend with an HTML/CSS/JavaScript interface to manage distributed scooter charging stations and process secure prepaid payments for battery charging services. It seeks to provide a seamless experience for electric scooter users—allowing them to locate chargers quickly, reserve a port, and pay in advance—while ensuring city operators maintain visibility and control over charging assets.

The target audience includes individual scooter owners, rental fleet operators, and municipal smart-city programs seeking to expand eco-friendly transportation. Riders benefit from reduced charging downtime and guaranteed charger availability, while operators gain powerful tools to optimize infrastructure usage, monitor device health and energy consumption, and analyze operational performance. By simplifying access to charging, the system supports the broader adoption of sustainable mobility solutions.

Innovation is a significant focus of GMU’s platform. IoT-enabled charging ports communicate directly with the Node.js management server, enabling dynamic pricing, automated billing per kilowatt-hour, and remote lock/unlock capabilities. The architecture is designed for future expansion, including predictive maintenance powered by analytics, secure integration with smart-grid providers, and user incentive programs that promote environmentally responsible travel. Its long-term goal is to create a highly connected micromobility ecosystem that contributes to reducing urban pollution.

However, a recent technology readiness assessment revealed multiple critical vulnerabilities that prevent deployment of the system in its current form. These include weak authentication and authorization flows, unencrypted communication between chargers and the backend, and insecure handling of financial data. The platform also lacks proper input validation, exposing it to common web attacks such as SQL injection, cross-site scripting, and request tampering. As a result, GMU Smart Mobility Solutions has contracted our company to perform a comprehensive cybersecurity analysis and propose modifications to both the source code and the overall system architecture to ensure a secure and resilient launch.

---

## Project Structure

The GMU Smart Scooter Charging System is organized into a lightweight **Node.js + Express** backend paired with a clean **HTML/CSS/JavaScript** frontend.  
The backend, implemented in `server.js`, is responsible for handling user authentication, charger station management, feedback submissions, and account features. The application uses **SQLite** as an embedded database, initialized upon startup with tables for users, charging stations, and user feedback. The backend exposes a set of **REST API** endpoints that support account creation, login, querying charging stations, updating user information, and retrieving administrative data.

The frontend resides in the `public/` directory and consists of two primary pages:
- `index.html` — Login and registration
- `dashboard.html` — User dashboard after authentication

These pages are visually styled using `style.css` and driven by a single JavaScript file, `app.js`, which handles form submission, UI rendering, and communication with backend APIs. Data is dynamically displayed, enabling interactive functionality such as station search, feedback viewing, account updates, and administrative listing.

To maintain state during user sessions, the system includes a simple session mechanism associating authenticated users with a session token. The frontend presents this token with requests made to backend endpoints requiring authentication. Together, these components form a clear, modular structure suitable for teaching web application security concepts: an API-centric backend, a script-driven UI, and a self-contained database for simple deployment and controlled classroom experimentation.

---
