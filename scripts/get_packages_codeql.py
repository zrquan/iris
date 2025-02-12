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
 
 from Package p
 select p.getName() as name
    """.strip()
    
    with open(query_path, 'w') as f:
        f.write(query)

def main():
    if len(sys.argv) != 2:
        print("Usage: python get_packages_codeql.py <project_name>")
        sys.exit(1)

    project_name = sys.argv[1]
    iris_root = Path(__file__).parent.parent
    output_file = iris_root / "data" / "cwe-bench-java" / "package-names" / f"{project_name}.txt"
    query_path = iris_root / "scripts" / "packages.ql"
    db_path = iris_root / "data" / "codeql-dbs" / project_name
     
    # Create query file
    create_codeql_query(query_path)
    
    try:
        print(f"Running get internal packages query on {project_name}...")
        
        # Run codeql query directly with bqrs output
        result = subprocess.run(
            ["codeql", "query", "run", "--database", str(db_path), 
             "--output=results.bqrs", str(query_path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        print("\nQuery completed. Getting results...")
        
        result = subprocess.run(
            ["codeql", "bqrs", "decode", "--format=csv", "results.bqrs"],
            capture_output=True,
            text=True,
            check=True
        )
        
        print("Raw output:")
        print(result.stdout)
        
        package_names = set()
        for line in result.stdout.strip().split('\n')[1:]: 
            if line.strip():
                package_names.add(line.strip().strip('"'))
        
        package_names = sorted(package_names)
        with open(output_file, 'w') as f:
            for package in package_names:
                f.write(f"{package}\n")
        
        print(f"\nFound {len(package_names)} packages. Results written to {output_file}")
        
    except subprocess.CalledProcessError as e:
        print(f"Error running CodeQL command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
    finally:
        # Clean up temporary files
        if query_path.exists():
            query_path.unlink()
        if Path("results.bqrs").exists():
            Path("results.bqrs").unlink()

if __name__ == "__main__":
    main()
