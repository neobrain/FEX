#pragma once

#include <clang/Frontend/FrontendAction.h>

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct FunctionParams {
    std::vector<clang::QualType> param_types;
};

struct ThunkedCallback : FunctionParams {
    clang::QualType return_type;

    bool is_stub = false;  // Callback will be replaced by a stub that calls std::abort
    bool is_guest = false; // Callback will never be called on the host
    bool is_variadic = false;
};

struct ParameterAnnotations {
    bool operator==(const ParameterAnnotations&) const = default;
};

/**
 * Guest<->Host transition point.
 *
 * These are normally used to translate the public API of the guest to host
 * function calls (ThunkedAPIFunction), but a thunk library may also define
 * internal thunks that don't correspond to any function in the implemented
 * API.
 */
struct ThunkedFunction : FunctionParams {
    std::string function_name;
    clang::QualType return_type;

    // If true, param_types contains an extra size_t and the valist for marshalling through an internal function
    bool is_variadic = false;

    // If true, the unpacking function will call a custom fexfn_impl function
    // to be provided manually instead of calling the host library function
    // directly.
    // This is implied e.g. for thunks generated for variadic functions
    bool custom_host_impl = false;

    std::string GetOriginalFunctionName() const {
        const std::string suffix = "_internal";
        assert(function_name.length() > suffix.size());
        assert((std::string_view { &*function_name.end() - suffix.size(), suffix.size() } == suffix));
        return function_name.substr(0, function_name.size() - suffix.size());
    }

    // Maps parameter index to ThunkedCallback
    std::unordered_map<unsigned, ThunkedCallback> callbacks;

    // Maps parameter index to ParameterAnnotations
    // TODO: Use index -1 for the return value?
    std::unordered_map<unsigned, ParameterAnnotations> param_annotations;

    clang::FunctionDecl* decl;
};

/**
 * Function that is part of the API of the thunked library.
 *
 * For each of these, there is:
 * - A publicly visible guest entrypoint (usually auto-generated but may be manually defined)
 * - A pointer to the native host library function loaded through dlsym (or a user-provided function specified via host_loader)
 * - A ThunkedFunction with the same function_name (possibly suffixed with _internal)
 */
struct ThunkedAPIFunction : FunctionParams {
    std::string function_name;

    clang::QualType return_type;

    // name of the function to load the native host symbol with
    std::string host_loader;

    // If true, no guest-side implementation of this function will be autogenerated
    bool custom_guest_impl;

    bool is_variadic;

    // Index of the symbol table to store this export in (see guest_symtables).
    // If empty, a library export is created, otherwise the function is entered into a function pointer array
    std::optional<std::size_t> symtable_namespace;
};

struct NamespaceInfo {
    clang::DeclContext* context;

    std::string name;

    // Function to load native host library functions with.
    // This function must be defined manually with the signature "void* func(void*, const char*)"
    std::string host_loader;

    bool generate_guest_symtable;

    bool indirect_guest_calls;
};

class AnalysisAction : public clang::ASTFrontendAction {
public:
    AnalysisAction() {
        decl_contexts.push_back(nullptr); // global namespace (replaced by getTranslationUnitDecl later)
    }

    void ExecuteAction() override;

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance&, clang::StringRef /*file*/) override;

protected:
    // Build the internal API representation by processing fex_gen_config and other annotated entities
    void ParseInterface(clang::ASTContext&);

    // Recursively extend the type set to include types of struct members
    void CoverReferencedTypes(clang::ASTContext&);

    // Called from ExecuteAction() after parsing is complete
    virtual void EmitOutput(clang::ASTContext&) {};

    std::vector<clang::DeclContext*> decl_contexts;

    std::vector<ThunkedFunction> thunks;
    std::vector<ThunkedAPIFunction> thunked_api;

    std::unordered_set<const clang::Type*> funcptr_types;

public: // TODO: Remove, make only RepackedType public
    struct RepackedType {
    };

    std::unordered_map<const clang::Type*, RepackedType> types;
    std::optional<unsigned> lib_version;
    std::vector<NamespaceInfo> namespaces;

    RepackedType& LookupType(clang::ASTContext& context, const clang::Type* type) {
      return types.at(context.getCanonicalType(type));
    }
};

inline std::string get_type_name(const clang::ASTContext& context, const clang::Type* type) {
    if (type->isBuiltinType()) {
        // Skip canonicalization
        return clang::QualType { type, 0 }.getAsString();
    }

    if (auto decl = type->getAsTagDecl()) {
        // Replace unnamed types with a placeholder. This will fail to compile if referenced
        // anywhere in generated code, but at least it will point to a useful location.
        //
        // A notable exception are C-style struct declarations like "typedef struct (unnamed) { ... } MyStruct;".
        // A typedef name is associated with these for linking purposes, so
        // getAsString() will produce a usable identifier.
        // TODO: Consider turning this into a hard error instead of replacing the name
        if (!decl->getDeclName() && !decl->getTypedefNameForAnonDecl()) {
            auto loc = context.getSourceManager().getPresumedLoc(decl->getLocation());
            std::string filename = loc.getFilename();
            filename = std::move(filename).substr(filename.rfind("/"));
            filename = std::move(filename).substr(1);
            std::replace(filename.begin(), filename.end(), '.', '_');
            return "unnamed_type_" + filename + "_" + std::to_string(loc.getLine());
        }
    }

    auto type_name = clang::QualType { context.getCanonicalType(type), 0 }.getAsString();
    if (type_name.starts_with("struct ")) {
        type_name = type_name.substr(7);
    }
    if (type_name.starts_with("class ") || type_name.starts_with("union ")) {
        type_name = type_name.substr(6);
    }
    if (type_name.starts_with("enum ")) {
        type_name = type_name.substr(5);
    }
    return type_name;
}
