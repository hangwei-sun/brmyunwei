import {
  Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";

export function OverviewTrend({ data }) {
  return <ResponsiveContainer width="100%" height={150}><LineChart data={data}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="time" tick={{ fontSize: 10 }} interval={5} /><YAxis tick={{ fontSize: 10 }} /><Tooltip /><Line type="monotone" dataKey="cpu" stroke="#1463df" dot={false} strokeWidth={2} /><Line type="monotone" dataKey="latency" stroke="#16a35a" dot={false} strokeWidth={2} /></LineChart></ResponsiveContainer>;
}

export function MetricTrend({ data, dataKey, stroke = "#1463df" }) {
  return <ResponsiveContainer width="100%" height={112}><AreaChart data={data}><CartesianGrid stroke="#e8edf4" vertical={false} /><XAxis dataKey="time" hide /><YAxis tick={{ fontSize: 10 }} width={28} /><Tooltip /><Area type="monotone" dataKey={dataKey} stroke={stroke} fill="none" strokeWidth={2} /></AreaChart></ResponsiveContainer>;
}

