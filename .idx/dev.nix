{pkgs}: {
  #channel = "stable-23.05"; # "stable-23.05" or "unstable"
  packages = [
    pkgs.go
    pkgs.gopls
    pkgs.go-tools
  ];
  idx.extensions = [
    "golang.Go"
    "r3inbowari.gomodexplorer"
    "pinage404.bash-extension-pack"
    "premparihar.gotestexplorer"
    "jeff-hykim.better-go-syntax"
    "vscodevim.vim"
    ];
  #idx.previews = {
   # enable = true;
    #previews = [
     # {
      #  command = ["go","run","vscpweb.go", "--port", "$PORT"]
       # manager = "web";
       # id = "web";
      #}
    #];
  #};
}