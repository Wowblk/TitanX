import { useLocation, useNavigate } from "react-router-dom";
import UserBadge from "@/components/common/UserBadge";
import { useAuth } from "@/context/AuthContext";
import styles from "./AuthStatus.module.css";

const AuthStatus = () => {
  const { user, logout, isLoading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  if (isLoading) {
    return <div style={{ color: "var(--color-text-muted)", fontSize: 13 }}>加载中...</div>;
  }

  if (!user) {
    return (
      <button
        type="button"
        className="ghost-button"
        onClick={() =>
          navigate("/login", {
            replace: false,
            state: { from: location.pathname + location.search + location.hash }
          })
        }
      >
        登录
      </button>
    );
  }

  const displayName = user.nickname || "用户";
  const avatarUrl = user.avatar || undefined;

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("退出登录失败", error);
    }
  };

  return (
    <div className={styles.wrapper}>
      <UserBadge name={displayName} avatarUrl={avatarUrl} />
      <button type="button" className={styles.logoutButton} onClick={handleLogout}>
        退出
      </button>
    </div>
  );
};

export default AuthStatus;
