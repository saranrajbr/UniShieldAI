import { createBrowserRouter } from "react-router-dom";
import { AppFrame } from "../components/layout/AppFrame";
import Overview from "../pages/Overview";
import Alerts from "../pages/Alerts";
import Traffic from "../pages/Traffic";
import Investigation from "../pages/Investigation";
import Engine from "../pages/Engine";
import About from "../pages/About";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppFrame />,
    children: [
      { index: true, element: <Overview /> },
      { path: "alerts", element: <Alerts /> },
      { path: "traffic", element: <Traffic /> },
      { path: "engine", element: <Engine /> },
      { path: "about", element: <About /> },
      { path: "investigation/:id", element: <Investigation /> },
    ],
  },
]);