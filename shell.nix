with (import <nixpkgs> {});
mkShell {
  buildInputs = [
    python311
    python311Packages.case
    python311Packages.future
  ];
}
