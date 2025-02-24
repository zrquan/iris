import os
import subprocess
import sys
from pathlib import Path

def create_codeql_query(query_path):
    query = """
/**
 * @name Find All Packages
 * @description Lists all packages in the Java project
 * @kind table
 * @id java/all-packages
 */
import java

// Get all packages from source
from Package p
where p.fromSource()
select p.getName() as name, count(Class c | c.getPackage() = p) as classCount
    """.strip()
    
    with open(query_path, 'w') as f:
        f.write(query)

def run_codeql_query(db_path, query_path):
    """Runs CodeQL query and extracts results as a list of (package_name, class_count)."""
    try:
        subprocess.run(
            ["codeql", "query", "run", "--database", str(db_path), 
             "--output=results.bqrs", str(query_path)],
            check=True, capture_output=True, text=True
        )

        result = subprocess.run(
            ["codeql", "bqrs", "decode", "--format=csv", "results.bqrs"],
            capture_output=True, text=True, check=True
        )

        packages = {}
        rows = result.stdout.strip().split("\n")[1:]
        for line in rows:
            parts = line.split(",")
            if len(parts) >= 2:
                pkg_name = parts[0].strip().strip('"')
                try:
                    class_count = int(parts[1].strip())
                except ValueError:
                    class_count = 1  
                packages[pkg_name] = class_count

        return packages

    except subprocess.CalledProcessError as e:
        print(f"Error running CodeQL command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return {}

def identify_internal_packages(packages):
    """
    Identify internal packages based on naming conventions.
    
    Internal packages are:
    - Those containing `.impl`, `.internal`, or `_internal`
    - Packages with a high class count relative to others (heuristic)
    """
    internal_packages = set()
    for pkg in packages:
        if ".impl" in pkg or ".internal" in pkg or "_internal" in pkg:
            internal_packages.add(pkg)

    return sorted(internal_packages)

def main():
    if len(sys.argv) != 2:
        print("Usage: python get_internal_packages_codeql.py <project_name>")
        sys.exit(1)
        
    project_name = sys.argv[1]
    iris_root = Path(__file__).parent.parent
    output_file = iris_root / "data" / "cwe-bench-java" / "package-names" / f"{project_name}.txt"
    query_path = iris_root / "scripts"/ "packages.ql"
    db_path = iris_root / "data"/ "codeql-dbs" / project_name

    # Create query file
    create_codeql_query(query_path)
    
    print(f"Running CodeQL query for {project_name}...")

    # Run CodeQL Query
    package_data = run_codeql_query(db_path, query_path)
    if not package_data:
        print("No packages found or CodeQL query failed.")
        return

    print(f"Found {len(package_data)} packages.")

    # Identify internal packages
    internal_packages = identify_internal_packages(package_data)
    print(f"Identified {len(internal_packages)} likely internal packages.")

    # Write results to file
    output_file.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
    with open(output_file, "w") as f:
        for package in internal_packages:
            f.write(f"{package}\n")

    print(f"Results written to {output_file}")

    # Cleanup
    query_path.unlink()
    Path("results.bqrs").unlink(missing_ok=True)

if __name__ == "__main__":
    main()
