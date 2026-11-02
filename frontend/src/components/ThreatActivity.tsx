import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend, LineChart, Line, XAxis, YAxis, CartesianGrid } from "recharts";
import { SEVERITY_COLORS, formatDate } from "../lib/format";
import type { TimelineData, RangeOption } from "../types";
import type { Dashboard } from "../hooks/useDashboard";

type ThreatActivityProps = Pick<
  Dashboard,
  | "severityData"
  | "timelineData"
  | "availableDays"
  | "selectedRange"
  | "setSelectedRange"
>;

export function ThreatActivity({
  severityData,
  timelineData,
  availableDays,
  selectedRange,
  setSelectedRange,
}: ThreatActivityProps) {
  return (
    <section className="dashboard-grid">

      <div className="panel large">

        <div className="panel-header">

          <div>

            <h2>
              Threat Activity
            </h2>

            <div className="chart-subtitle">
              CVE publication activity
            </div>

          </div>


          <div className="chart-controls">

            <span className="chart-source">
              NVD
            </span>


            <div className="range-selector">

              {[7, 30, 90].map(
                (range) => (

                  <button
                    key={range}
                    className={
                      selectedRange === range
                        ? "range-button active"
                        : "range-button"
                    }
                    onClick={() =>
                      setSelectedRange(
                        range as RangeOption
                      )
                    }
                  >
                    {range}D
                  </button>

                )
              )}

            </div>

          </div>

        </div>


        <div className="chart-meta">

          <span>
            Daily publications
          </span>

          <span>
            7-day moving average
          </span>


          {selectedRange === 90 &&
            availableDays < 90 && (

              <span className="data-warning">
                {availableDays}D DATA
                AVAILABLE
              </span>

            )}

        </div>


        <div
          style={{
            width: "100%",
            height: 300,
          }}
        >

          <ResponsiveContainer>

            <LineChart
              data={timelineData}
              margin={{
                top: 10,
                right: 12,
                left: 0,
                bottom: 5,
              }}
            >

              <CartesianGrid
                strokeDasharray="2 6"
                stroke="#1a2230"
                vertical={false}
              />

              <XAxis
                dataKey="date"
                tick={{
                  fontSize: 10,
                  fill: "#657189",
                }}
                tickFormatter={
                  formatDate
                }
                tickLine={false}
                axisLine={{
                  stroke:
                    "#202735",
                }}
              />

              <YAxis
                allowDecimals={false}
                tick={{
                  fontSize: 10,
                  fill: "#657189",
                }}
                tickLine={false}
                axisLine={false}
              />

              <Tooltip
                content={({
                  active,
                  payload,
                  label,
                }) => {

                  if (
                    !active ||
                    !payload ||
                    payload.length === 0
                  ) {
                    return null;
                  }


                  const data =
                    payload[0]
                      ?.payload as TimelineData;


                  if (!data) {
                    return null;
                  }


                  return (

                    <div className="custom-tooltip">

                      <div className="tooltip-date">

                        {formatDate(
                          String(label ?? "")
                        )}

                      </div>


                      <div className="tooltip-row">

                        <span>
                          CVEs published
                        </span>

                        <strong>
                          {data.count}
                        </strong>

                      </div>


                      <div className="tooltip-row">

                        <span>
                          7-day average
                        </span>

                        <strong>
                          {
                            data.movingAverage
                          }
                        </strong>

                      </div>

                    </div>

                  );
                }}
              />


              <Line
                type="monotone"
                dataKey="count"
                name="Published CVEs"
                stroke="#38bdf8"
                strokeWidth={2}
                dot={{
                  r: 2.5,
                  fill: "#38bdf8",
                }}
                activeDot={{
                  r: 5,
                }}
              />


              <Line
                type="monotone"
                dataKey="movingAverage"
                name="7-day average"
                stroke="#a78bfa"
                strokeWidth={2}
                strokeDasharray="6 4"
                dot={false}
              />

            </LineChart>

          </ResponsiveContainer>

        </div>

      </div>


      <div className="panel">

        <div className="panel-header">

          <h2>
            Severity Distribution
          </h2>

        </div>


        <div
          style={{
            width: "100%",
            height: 300,
          }}
        >

          <ResponsiveContainer>

            <PieChart>

              <Pie
                data={severityData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="43%"
                innerRadius={48}
                outerRadius={88}
                paddingAngle={2}
              >

                {severityData.map(
                  (
                    entry,
                    index
                  ) => (

                    <Cell
                      key={`cell-${index}`}
                      fill={
                        SEVERITY_COLORS[
                          entry.name
                        ]
                      }
                    />

                  )
                )}

              </Pie>


              <Tooltip
                contentStyle={{
                  backgroundColor:
                    "#0d111a",
                  border:
                    "1px solid #202735",
                  borderRadius:
                    "6px",
                  color:
                    "#ffffff",
                }}
                formatter={(
                  value,
                  name
                ) => [
                  `${value} CVEs`,
                  name,
                ]}
              />


              <Legend
                verticalAlign="bottom"
                height={55}
                formatter={(value) => {

                  const item =
                    severityData.find(
                      (entry) =>
                        entry.name ===
                        String(value ?? "")
                    );


                  const label = String(value ?? "");

                  return `${label}: ${
                    item?.value ?? 0
                  }`;

                }}
              />

            </PieChart>

          </ResponsiveContainer>

        </div>

      </div>

    </section>
  );
}
