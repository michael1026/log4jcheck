# log4jcheck

### Install
```
go install https://github.com/michael1026/log4jcheck@latest
```

### Example Usage
```
cat URLs | log4jcheck -user-agent -referer -server example.burpcollaborator.net
```

### Notes
`-struts` will change the path and append the payload from this post: https://twitter.com/testanull/status/1469549425521348609
I would not use this flag for basic checks. 

I also recommend using `-user-agent` and `-referer` seperately as one header sometimes causes 400 Bad Requests, invalidating your tests.
