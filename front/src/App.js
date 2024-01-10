import { Route, Routes, Navigate } from "react-router-dom";
import Signup from "./components/Singup";
import Login from "./components/Login";
import EmailVerify from "./components/EmailVerify";
import 'bootstrap/dist/css/bootstrap.css';

function App() {
	const user = localStorage.getItem("token");

	return (
		<Routes>
			<Route path="/signup" element={<Signup />} />
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Navigate replace to="/login" />} />
            <Route path="/users/:id/verify/:token" element={<EmailVerify />} />
		</Routes>
	);
}

export default App;