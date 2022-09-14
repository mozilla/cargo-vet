import React, {
  useReducer,
  useContext,
  useId,
  useMemo,
  useRef,
  useState,
  useEffect,
} from "react";
import ReactDOM from "react-dom/client";
import "bootstrap/scss/bootstrap.scss";
import pako from "pako";

// NOTE: This is a very hacky initial take at building a GUI for cargo vet, and
// can probably be improved substantially!

function initAudits({ allCriteria, suggested }) {
  return suggested.map((pkg) => ({
    name: pkg.name,
    delta: pkg.delta,
    criteria: allCriteria.flatMap((ci) => {
      if (
        pkg.initialCriteria.includes(ci.name) ||
        ci.impliedBy.some((implied) => pkg.initialCriteria.includes(implied))
      ) {
        return [ci.name];
      } else {
        return [];
      }
    }),
    notes: "",
    certified: false,
  }));
}

function auditsReducer(allCriteria, state, action) {
  const updateAudit = (idx, cb) => [
    ...state.slice(0, idx),
    cb(state[idx]),
    ...state.slice(idx + 1),
  ];

  switch (action.type) {
    // Enable a criteria for a given package
    case "add-criteria":
      return updateAudit(action.pkgIdx, (pkg) => ({
        ...pkg,
        criteria: allCriteria.flatMap((ci) => {
          if (
            action.criteriaName == ci.name ||
            ci.impliedBy.includes(action.criteriaName) ||
            pkg.criteria.includes(ci.name)
          ) {
            return [ci.name];
          } else {
            return [];
          }
        }),
        certified: false,
      }));
    // Disable a criteria for a given package
    case "remove-criteria":
      return updateAudit(action.pkgIdx, (pkg) => ({
        ...pkg,
        criteria: pkg.criteria.filter((name) => name != action.criteriaName),
        certified: false,
      }));
    // Update the recorded notes for a package
    case "set-notes":
      return updateAudit(action.pkgIdx, (pkg) => ({
        ...pkg,
        notes: action.notes,
      }));
    // Set whether or not a package is certified
    case "set-certified":
      return updateAudit(action.pkgIdx, (pkg) => ({
        ...pkg,
        certified: action.certified,
      }));
    default:
      throw new Error();
  }
}

const AllCriteria = React.createContext([]);

function PkgHeader({ pkg }) {
  let sourcegraphUrl;
  if (pkg.delta.includes("->")) {
    const [from, to] = pkg.delta.split("->").map((s) => s.trim());
    sourcegraphUrl = `https://sourcegraph.com/crates/${pkg.name}/-/compare/v${from}...v${to}`;
  } else {
    sourcegraphUrl = `https://sourcegraph.com/crates/${pkg.name}@v${pkg.delta}`;
  }
  return (
    <div className="card-header">
      <div className="d-flex justify-content-between align-items-center">
        <div>
          <code>
            {pkg.name} {pkg.delta}
          </code>
        </div>
        <a className="btn btn-primary" href={sourcegraphUrl} target="_blank">
          Inspect on SourceGraph
        </a>
      </div>
    </div>
  );
}

function CriteriaCheckbox({ criteriaName, checked, disabled, dispatch }) {
  const id = useId();
  return (
    <li className="list-group-item">
      <input
        id={id}
        type="checkbox"
        className="form-check-input me-1"
        checked={checked}
        disabled={disabled}
        onChange={(e) =>
          dispatch({
            type: e.target.checked ? "add-criteria" : "remove-criteria",
            criteriaName,
          })
        }
      ></input>
      <label className="form-check-label" htmlFor={id}>
        {criteriaName}
      </label>
    </li>
  );
}

function PkgBodyOptions({ pkg, dispatch }) {
  const allCriteria = useContext(AllCriteria);
  return (
    <div className="col-lg-3">
      <label className="form-label">Criteria</label>
      <ul className="list-group">
        {allCriteria.map((criteriaInfo) => {
          const checked = pkg.criteria.includes(criteriaInfo.name);
          const disabled = criteriaInfo.impliedBy.some((impliedBy) =>
            pkg.criteria.includes(impliedBy)
          );
          return (
            <CriteriaCheckbox
              key={criteriaInfo.name}
              criteriaName={criteriaInfo.name}
              checked={checked}
              disabled={disabled}
              dispatch={dispatch}
            />
          );
        })}
      </ul>
      <label className="form-label mt-3">Notes</label>
      <textarea
        className="form-control"
        value={pkg.notes}
        onChange={(e) => dispatch({ type: "set-notes", notes: e.target.value })}
      ></textarea>
    </div>
  );
}

function PkgBodyEulas({ pkg }) {
  const allCriteria = useContext(AllCriteria);
  return (
    <div className="col-lg-9">
      <h2>Eulas</h2>
      <p>Please read the following criteria which are being certified:</p>
      {allCriteria.flatMap((criteriaInfo) => {
        const selected = pkg.criteria.includes(criteriaInfo.name);
        const implied = criteriaInfo.impliedBy.some((impliedBy) =>
          pkg.criteria.includes(impliedBy)
        );
        if (!selected || implied) {
          return [];
        }
        return [
          <div key={criteriaInfo.name}>
            <h3>{criteriaInfo.name}</h3>
            <pre>{criteriaInfo.description}</pre>
          </div>,
        ];
      })}
    </div>
  );
}

function PkgBody({ pkg, dispatch }) {
  return (
    <div className="card-body">
      <div className="row">
        <PkgBodyOptions pkg={pkg} dispatch={dispatch} />
        <PkgBodyEulas pkg={pkg} />
      </div>
    </div>
  );
}

function PkgFooter({ pkg, dispatch }) {
  const id = useId();
  return (
    <div className={"card-footer " + (pkg.certified ? "" : "text-bg-warning")}>
      <input
        id={id}
        type="checkbox"
        className="form-check-input me-1"
        checked={pkg.certified}
        onChange={(e) =>
          dispatch({ type: "set-certified", certified: e.target.checked })
        }
      />
      <label className="form-check-label" htmlFor={id}>
        I certify that I have audited{" "}
        <code>
          {pkg.name} {pkg.delta}
        </code>{" "}
        in accordance with the above criteria
      </label>
    </div>
  );
}

function CriteriaSelector({ pkg, dispatch }) {
  return (
    <div
      className={
        "card mt-2 " + (pkg.certified ? "border-success" : "border-warning")
      }
    >
      <PkgHeader pkg={pkg} />
      <PkgBody pkg={pkg} dispatch={dispatch} />
      <PkgFooter pkg={pkg} dispatch={dispatch} />
    </div>
  );
}

function buildResult(audits) {
  const json = JSON.stringify({
    audits: audits
      .filter((pkg) => pkg.certified)
      .map((pkg) => ({
        name: pkg.name,
        delta: pkg.delta,
        criteria: pkg.criteria,
        notes: pkg.notes,
      })),
  });
  const jsonEncoded = new TextEncoder().encode(json);
  const compressed = pako.gzip(jsonEncoded);
  return btoa("gzip;" + String.fromCharCode(...compressed));
}

function ResultDisplay({ audits }) {
  const resultsEl = useRef(null);
  const uncertified = audits.filter((pkg) => !pkg.certified);
  const result = useMemo(() => buildResult(audits), [audits]);
  return (
    <div className="card mt-2">
      <div
        className={
          "card-header " +
          (uncertified.length ? "text-bg-warning" : "text-bg-success")
        }
      >
        <div className="d-flex justify-content-between align-items-center">
          <div>
            {uncertified.length
              ? "Packages Missing Certification!"
              : "All Packages Certified"}
          </div>
          <a
            className="btn btn-primary"
            onClick={(e) => {
              resultsEl.current.select();
              document.execCommand("copy");
            }}
          >
            Copy Results
          </a>
        </div>
      </div>
      {!!uncertified.length && (
        <div className="card-body">
          {uncertified.length} audits are uncertified:
          {uncertified.map((pkg) => (
            <div
              key={`${pkg.name} ${pkg.delta}`}
              className="badge text-bg-danger ms-1"
            >
              {pkg.name} {pkg.delta}
            </div>
          ))}
        </div>
      )}
      <div className="card-footer">
        <textarea
          ref={resultsEl}
          className="form-control"
          readOnly
          value={result}
        />
      </div>
    </div>
  );
}

function CertifyUICore(props) {
  const [audits, dispatch] = useReducer(
    (state, action) => auditsReducer(props.allCriteria, state, action),
    props,
    initAudits
  );
  return (
    <AllCriteria.Provider value={props.allCriteria}>
      {audits.map((pkg, idx) => (
        <CriteriaSelector
          key={idx}
          pkg={pkg}
          dispatch={(action) => dispatch({ ...action, pkgIdx: idx })}
        />
      ))}
      <ResultDisplay audits={audits} />
    </AllCriteria.Provider>
  );
}

// Read the input state from the URL's hash, decode and decompress it, and
// return the result.
function readInput() {
  try {
    let state = window.location.hash.slice(1);
    let data = atob(state);
    if (!data.startsWith("gzip;")) {
      throw new Error("unsupported input state format");
    }
    data = data.slice(5);
    const uncompressed = pako.inflate(
      Uint8Array.from(data, (c) => c.charCodeAt(0)),
      { to: "string" }
    );
    return JSON.parse(uncompressed);
  } catch (e) {
    return {
      error: "" + e,
    };
  }
}

function CertifyUI() {
  const [input, setInput] = useState(readInput);
  const onHashChange = () => {
    setInput(readInput());
  };
  useEffect(() => {
    window.addEventListener("hashchange", onHashChange);
    return () => {
      window.removeEventListener("hashchange", onHashChange);
    };
  }, []);

  if (input.audits && input.criteria) {
    return (
      <CertifyUICore suggested={input.audits} allCriteria={input.criteria} />
    );
  } else {
    return (
      <div>
        <div className="alert alert-danger" role="alert">
          <h1>Unable to parse input state</h1>
          {input.error}
        </div>
        <div className="alert alert-warning">
          The URL may be incorrect or malformed.
        </div>
      </div>
    );
  }
}

function App() {
  return (
    <div className="container">
      <h1>
        <code>cargo vet certify</code>
      </h1>
      <CertifyUI />
      <footer className="pt-3 pb-3 text-muted text-center">
        ui generated by cargo-vet-gui &mdash;{" "}
        <a
          href="https://mozilla.github.io/cargo-vet"
          className="link-secondary"
        >
          what is cargo-vet?
        </a>
      </footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
