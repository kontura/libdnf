%module(directors="1") utils

%begin %{
#define SWIG_PYTHON_2_UNICODE
%}

%include <exception.i>
%include <std_shared_ptr.i>
%include <std_string.i>


%{
    // make SWIG wrap following headers
    #include "libdnf/utils/sqlite3/Sqlite3.hpp"
    #include "libdnf/utils/logger.hpp"
    #include "libdnf/log.hpp"
    #include "libdnf/utils/utils.hpp"
%}


%exception {
    try {
        $action
    } catch (const std::exception & e) {
       SWIG_exception(SWIG_RuntimeError, e.what());
    }
}

%shared_ptr(SQLite3)
%nocopyctor SQLite3;


// make SWIG look into following headers
class SQLite3 {
public:
    SQLite3(const SQLite3 &) = delete;
    SQLite3 & operator=(const SQLite3 &) = delete;
    SQLite3(const char *dbPath);
    void close();
};

typedef long time_t;
typedef long pid_t;

%feature("director") Logger;
%include "libdnf/utils/logger.hpp"

%include "libdnf/log.hpp"

typedef int mode_t;

namespace libdnf { namespace filesystem {

void decompress(const char * inPath, const char * outPath, mode_t outMode, const char * compressType = nullptr);

}}
